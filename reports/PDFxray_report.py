#!/usr/bin/env python3

import json
import hashlib
import os
import re
import sys
from datetime import datetime
from openpyxl import Workbook


def generate_report(pdf_path):

    if not os.path.exists(pdf_path):
        print(f"[ERROR] File not found: {pdf_path}")
        return

    with open(pdf_path, "rb") as f:
        data = f.read()

    filename = os.path.basename(pdf_path)
    file_stem = os.path.splitext(filename)[0]

    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    version_match = re.search(rb'%PDF-(\d+\.\d+)', data)
    pdf_version = (
        version_match.group(1).decode("utf-8")
        if version_match
        else "Unknown"
    )

    objects = len(
        re.findall(rb'\d+\s+\d+\s+obj', data)
    )

    streams = len(
        re.findall(rb'\bstream\b', data)
    )

    js_count = data.count(b'/JavaScript')
    open_action = data.count(b'/OpenAction')
    launch_action = data.count(b'/Launch')
    embedded_files = data.count(b'/EmbeddedFile')

    verdict = "BENIGN"
    risk_level = "LOW"

    if (
        js_count > 0
        or open_action > 0
        or launch_action > 0
        or embedded_files > 0
    ):
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"

    report = {
        "filename": filename,
        "filepath": pdf_path,
        "size_bytes": len(data),
        "size_kb": round(len(data) / 1024, 2),
        "md5": md5,
        "sha256": sha256,
        "pdf_version": pdf_version,
        "objects": objects,
        "streams": streams,
        "javascript": js_count,
        "open_action": open_action,
        "launch_action": launch_action,
        "embedded_files": embedded_files,
        "risk_level": risk_level,
        "verdict": verdict,
        "analysis_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    # Create reports folder automatically
    os.makedirs("reports", exist_ok=True)

    # JSON Report
    json_name = os.path.join(
        "reports",
        f"{file_stem}_report.json"
    )

    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    # Excel Report
    wb = Workbook()
    ws = wb.active
    ws.title = "PDFXRay Report"

    ws.append(["Field", "Value"])

    for key, value in report.items():
        ws.append([key, str(value)])

    excel_name = os.path.join(
        "reports",
        f"{file_stem}_report.xlsx"
    )

    wb.save(excel_name)

    print("=" * 60)
    print("PDFXRAY REPORT")
    print("=" * 60)

    for k, v in report.items():
        print(f"{k}: {v}")

    print("\nJSON Saved :", json_name)
    print("Excel Saved:", excel_name)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("python PDFxray_report.py sample.pdf")
        sys.exit(1)

    generate_report(sys.argv[1])