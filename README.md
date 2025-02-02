# Janus Vulnerability Tester

This tool helps test Android APKs for the Janus vulnerability by analyzing their signature schemes and creating proof-of-concept files for testing purposes.

## Features

- Analyzes APK signature schemes (V1, V2, and V3)
- Determines vulnerability status based on signature presence
- Creates proof-of-concept APKs for testing
- Provides recommendations based on Android API levels

## Usage

```bash
# Basic APK analysis
go run main.go -apk path/to/your.apk

# Analysis with custom POC dex file
go run main.go -apk path/to/your.apk -dex path/to/poc.dex
```

## Understanding Results

The tool will analyze the APK and provide information about:
- Present signature schemes (V1, V2, V3)
- Vulnerability status
- Recommended Android API versions for testing
- Generate a POC APK if vulnerable

### Vulnerability Conditions

1. **Not Vulnerable**: APK has no V1 signature
2. **Potentially Vulnerable**: APK has V1 + V2/V3 signatures
   - Can be tested on Android API 22-23 (Android 5.1-6.0)
3. **Highly Vulnerable**: APK has only V1 signature
   - Vulnerable on Android versions below 7.0

## Safety Notice

This tool is for educational and testing purposes only. Always test APKs in a safe, controlled environment.

## Requirements

- Go 1.15 or higher
- Android test devices or emulators (recommended API levels: 22, 23)
- POC DEX file (optional)
- apksigner tool
