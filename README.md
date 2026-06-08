# PDFXRay

PDFXRay is a Python-based PDF malware analysis tool designed for educational and research purposes. The tool performs static analysis of PDF files and detects potentially suspicious indicators such as JavaScript actions, OpenAction triggers, embedded files, URLs, IP addresses, suspicious strings, and compressed streams.

This project was developed as part of PDF malware analysis learning and CEHv13 practice.

---

## Features

* PDF Structure Analysis
* Object Enumeration
* Stream Enumeration
* FlateDecode Stream Decompression
* JavaScript Detection
* OpenAction Detection
* Launch Action Detection
* Embedded File Detection
* URL Extraction
* IP Address Extraction
* Suspicious String Detection
* PDF Metadata Inspection
* JSON Report Generation
* Excel Report Generation
* Risk Assessment Reporting

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
├── reports/
│   └── PDFxray_report.py
│
└── samples/
    ├── benign_sample.pdf
    └── malicious_sample.pdf
```

---

## Requirements

* Python 3.10+
* Windows or Linux

Install required dependencies:

```bash
pip install -r requirements.txt
```

---

## requirements.txt

```txt
openpyxl>=3.1.5
pdfminer.six>=20231228
PyMuPDF>=1.26.0
yara-python>=4.5.0
pefile>=2024.8.26
```

---

## Usage

### Deep PDF Analysis

```bash
python deep_analyze.py sample.pdf
```

Example:

```bash
python deep_analyze.py "C:\Users\User\Downloads\sample.pdf"
```

---

### Generate Analysis Report

Generate JSON and Excel reports:

```bash
python reports/PDFxray_report.py sample.pdf
```

Example:

```bash
python reports/PDFxray_report.py "C:\Users\User\Downloads\sample.pdf"
```

---

## Sample Generation

Generate test PDF samples:

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

| Indicator          | Detection |
| ------------------ | --------- |
| JavaScript         | ✅         |
| OpenAction         | ✅         |
| Launch Action      | ✅         |
| Embedded File      | ✅         |
| URLs               | ✅         |
| IP Addresses       | ✅         |
| Suspicious Strings | ✅         |
| Compressed Streams | ✅         |
| PDF Objects        | ✅         |
| PDF Metadata       | ✅         |

---

## Generated Reports

The report generator automatically creates:

* JSON Report
* Excel Report (.xlsx)

Example:

```text
sample_report.json
sample_report.xlsx
```

---

## Example Output

```text
============================================================
PDFXRay REPORT
============================================================

filename: sample.pdf
size_bytes: 121137
pdf_version: 1.4

javascript: 0
open_action: 0
embedded_files: 0

verdict: BENIGN

JSON Saved : sample_report.json
Excel Saved: sample_report.xlsx
```

---

## Educational Purpose

This project was created to help students understand:

* PDF Internals
* Static Malware Analysis
* PDF Threat Hunting
* CEHv13 Concepts
* Secure Document Inspection
* Malware Analysis Methodology

---

## Disclaimer

This project is intended strictly for educational, research, and authorized security testing purposes.

Do not use this software against systems, files, or environments without proper authorization.

The author assumes no responsibility for misuse of this software.

---

## Future Improvements

* YARA Rule Scanning
* VirusTotal Integration
* IOC Extraction
* Entropy Analysis
* Embedded File Extraction
* PDF Risk Scoring Engine
* GUI Version (Tkinter / PyQt)

---

## Author

Rohan Kumar

Cybersecurity Student

CEHv13 Learner

PDF Malware Analysis Research Project

GitHub Portfolio Project

