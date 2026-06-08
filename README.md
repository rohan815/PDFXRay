# PDFXRay

PDFXRay is an educational PDF analysis tool built in Python for static PDF inspection. It helps identify potentially suspicious PDF indicators such as JavaScript actions, OpenAction triggers, embedded files, URLs, IP addresses, and suspicious strings.

> This project is intended for educational purposes, malware analysis learning, and CEHv13 practice.

---

## Features

- PDF Structure Analysis
- Object and Stream Enumeration
- FlateDecode Stream Decompression
- JavaScript Detection
- OpenAction Detection
- Launch Action Detection
- Embedded File Detection
- URL Extraction
- IP Address Extraction
- Suspicious String Detection
- PDF Metadata Inspection
- Risk Assessment Reporting

---

## Project Structure

```text
PDFXRay/
│
├── deep_analyze.py
├── create_samples.py
├── README.md
├── requirements.txt
│
└── samples/
    ├── benign_sample.pdf
    └── malicious_sample.pdf
```

---

## Requirements

- Python 3.10+
- Windows/Linux

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Analyze a PDF:

```bash
python deep_analyze.py sample.pdf
```

Analyze a specific file:

```bash
python deep_analyze.py "C:\Path\To\File.pdf"
```

---

## Sample Generation

Generate test PDFs:

```bash
python create_samples.py
```

Generated files:

```text
samples/
├── benign_sample.pdf
└── malicious_sample.pdf
```

---

## Detection Capabilities

PDFXRay checks for:

| Indicator | Detection |
|------------|------------|
| JavaScript | ✅ |
| OpenAction | ✅ |
| Launch Actions | ✅ |
| Embedded Files | ✅ |
| URLs | ✅ |
| IP Addresses | ✅ |
| Suspicious Strings | ✅ |
| Compressed Streams | ✅ |
| PDF Objects | ✅ |

---

## Example Output

```text
============================================================
DEEP ANALYSIS
============================================================

File: sample.pdf
Size: 120 KB

JavaScript: 0
OpenAction: 0
Embedded Files: 0

FINAL VERDICT:
FILE IS BENIGN
```

---

## Educational Purpose

This project was created to help students learn:

- PDF Internals
- Static Malware Analysis
- PDF Threat Hunting
- CEHv13 Concepts
- Secure Document Inspection

---

## Disclaimer

This tool is provided for educational and research purposes only.

Do not use this project to analyze files without proper authorization.

The author is not responsible for misuse of this software.

---

## Author

Rohan Kumar

Cybersecurity Student | CEHv13 Learner | PDF Malware Analysis Enthusiast
