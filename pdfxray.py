#!/usr/bin/env python3
"""
PDFXRay - Advanced PDF Malware Analysis Tool
CEHv13 Assessment Tool
Windows Compatible Version
"""

import sys
import os
import re
import hashlib
import json
import math
from collections import Counter
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════╗
║   ____  ______  _  _  __  __  ____  _  _  ___       ║
║  |  _ \\|  __ \\| || | \\ \\/ / |___ \\| || |/ _ \\      ║
║  | |_) | |__) | || |_ \\  /    __) | || | | | |     ║
║  |  _ <|  ___/ |__   _|/  \\  |__ <|__   _| | |     ║
║  | |_) | |        | | / /\\ \\ ___) |  | | | |_| |    ║
║  |____/|_|        |_|/_/  \\_\\____/   |_|  \\___/     ║
║                                                      ║
║  🔍 PDF Malware Analysis Suite - CEHv13             ║
║  ⚡ Version 1.0.0                                    ║
╚══════════════════════════════════════════════════════╝
"""

def calculate_entropy(data):

    if not data:
        return 0

    counter = Counter(data)
    length = len(data)

    entropy = 0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)

class PDFXRay:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = None
        self.report = {
            'filename': '',
            'filepath': '',
            'md5': '',
            'sha256': '',
            'file_size': 0,
            'entropy': 0,
            'pdf_version': '',
            'is_valid_pdf': False,
            'total_objects': 0,
            'total_streams': 0,
            'compressed_streams': 0,
            'suspicious_indicators': [],
            'risk_score': 0,
            'risk_level': 'LOW',
            'anomalies': [],
            'analysis_time': ''
        }
    
    def run(self):
        """Execute full analysis"""
        self.report['filename'] = self.filename
        self.report['filepath'] = self.filepath
        self.report['analysis_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            print(f"   ❌ Read error: {e}")
            return None
        
        # Hashes
        self.report['md5'] = hashlib.md5(self.data).hexdigest()
        self.report['sha256'] = hashlib.sha256(self.data).hexdigest()
        self.report['file_size'] = len(self.data)
        self.report['entropy'] = calculate_entropy(self.data)
        # Check PDF header
        if self.data[:5] == b'%PDF-':
            self.report['is_valid_pdf'] = True
            version_match = re.search(rb'%PDF-(\d+\.\d+)', self.data)
            if version_match:
                self.report['pdf_version'] = version_match.group(1).decode('utf-8')
            else:
                self.report['pdf_version'] = 'Unknown'
        else:
            self.report['is_valid_pdf'] = False
            return self.report
        
        # Count objects & streams
        objects = re.findall(rb'(\d+ \d+) obj', self.data)
        self.report['total_objects'] = len(objects)
        
        streams = re.findall(rb'stream', self.data)
        self.report['total_streams'] = len(streams)
        
        compressed = re.findall(rb'/Filter\s*/FlateDecode', self.data)
        self.report['compressed_streams'] = len(compressed)
        
        # Scan indicators
        self._scan_indicators()
        self._check_anomalies()
        self._calculate_risk()
        
        return self.report
    
    def _scan_indicators(self):
        indicators = {
            '/JavaScript': {'risk': 3, 'desc': 'JavaScript code present'},
            '/JS': {'risk': 3, 'desc': 'JavaScript shorthand'},
            '/OpenAction': {'risk': 4, 'desc': 'Auto-execute on open'},
            '/AA': {'risk': 3, 'desc': 'Additional Actions'},
            '/Launch': {'risk': 5, 'desc': 'Launch external app'},
            '/EmbeddedFile': {'risk': 3, 'desc': 'Embedded file'},
            '/ObjStm': {'risk': 2, 'desc': 'Object Stream'},
            '/AcroForm': {'risk': 1, 'desc': 'Interactive form'},
            '/XFA': {'risk': 2, 'desc': 'XML Forms'},
            '/URI': {'risk': 2, 'desc': 'URI action'},
            '/SubmitForm': {'risk': 2, 'desc': 'Form submission'},
            '/RichMedia': {'risk': 2, 'desc': 'Embedded Media'},
        }
        
        for keyword, info in indicators.items():
            count = len(
                re.findall(
                    re.escape(keyword.encode()) + rb'\b',
                    self.data
                )
            )

            if count > 0:
                self.report['suspicious_indicators'].append({
                    'keyword': keyword,
                    'description': info['desc'],
                    'risk_score': info['risk'],
                    'count': count
                })    
    def _check_anomalies(self):
        # Suspicious strings
        suspicious_strings = [
            (b'cmd.exe', 'Windows command'),
            (b'powershell', 'PowerShell'),
            (b'wscript', 'Windows Script Host'),
            (b'cscript', 'Console Script Host'),
            (b'mshta', 'Mshta'),
            (b'rundll32', 'Rundll32'),
            (b'http://', 'HTTP URL'),
            (b'https://', 'HTTPS URL'),
        ]
        
        for string, desc in suspicious_strings:
            if string in self.data:
                self.report['anomalies'].append(f"Suspicious: '{string.decode()}' - {desc}")
        
        # Check for MZ (PE file)
        if re.search(rb'\bMZ\b', self.data):
            self.report['anomalies'].append("MZ header - Possible embedded executable")
    
    def _calculate_risk(self):
        total_risk = 0
        for ind in self.report['suspicious_indicators']:
           total_risk += ind['risk_score'] * min(ind['count'], 3)
        total_risk += len(self.report['anomalies'])
        
        self.report['risk_score'] = min(total_risk, 20)
        
        if self.report['risk_score'] >= 15:
            self.report['risk_level'] = 'CRITICAL'
        elif self.report['risk_score'] >= 10:
            self.report['risk_level'] = 'HIGH'
        elif self.report['risk_score'] >= 5:
            self.report['risk_level'] = 'MEDIUM'
        else:
            self.report['risk_level'] = 'LOW'
    
    def display_report(self):
        risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        print("\n" + "=" * 55)
        print("📋 PDFXRay ANALYSIS REPORT")
        print("=" * 55)
        
        print(f"\n📄 File: {self.filename}")
        print(f"📏 Size: {self.report['file_size']:,} bytes")
        print(f"🔐 MD5: {self.report['md5']}")
        print(f"🔐 SHA256: {self.report['sha256'][:40]}...")
        print(f"📋 Version: {self.report['pdf_version']}")
        print(f"📈 Entropy: {self.report['entropy']}")
        
        print(f"\n📊 Structure:")
        print(f"   Objects: {self.report['total_objects']}")
        print(f"   Streams: {self.report['total_streams']}")
        
        if self.report['suspicious_indicators']:
            print(f"\n⚠️  Suspicious Indicators:")
            for ind in self.report['suspicious_indicators']:
                stars = '!' * min(ind['risk_score'], 5)
                print(f"   [{stars}] {ind['keyword']} (x{ind['count']})")
        
        if self.report['anomalies']:
            print(f"\n🚩 Anomalies:")
            for a in self.report['anomalies']:
                print(f"   [!] {a}")
        
        icon = risk_icons.get(self.report['risk_level'], '❓')
        print(f"\n{icon} Risk: {self.report['risk_level']} ({self.report['risk_score']}/20)")
        
        if self.report['risk_level'] == 'CRITICAL':
            print("   ⚠️  MALICIOUS - Do not open!")
        elif self.report['risk_level'] == 'HIGH':
            print("   ⚠️  Highly suspicious")
        elif self.report['risk_level'] == 'MEDIUM':
            print("   📝  Needs investigation")
        else:
            print("   ✅  Likely benign")
        
        print("\n" + "=" * 55)
    
    def save_json_report(self, output_dir='reports'):
        os.makedirs(output_dir, exist_ok=True)
        report_file = os.path.join(output_dir, f"{self.filename}_report.json")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=4)
        
        print(f"\n💾 Report saved: {report_file}")
        return report_file

def main():
    print(BANNER)
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python pdfxray.py <pdf_file>")
        print("  python pdfxray.py <pdf_file> --deep")
        print("  python pdfxray.py <pdf_file> --json")
        print("  python pdfxray.py <directory> --batch")
        print("\nExamples:")
        print("  python pdfxray.py sample.pdf")
        print("  python pdfxray.py samples/ --batch")
        sys.exit(1)
    
    target = sys.argv[1]
    deep_mode = '--deep' in sys.argv
    json_mode = '--json' in sys.argv
    batch_mode = '--batch' in sys.argv or os.path.isdir(target)
    
    if batch_mode:
        # Batch analysis
        directory = target if os.path.isdir(target) else '.'
        pdfs = [f for f in os.listdir(directory) if f.lower().endswith('.pdf')]
        
        if not pdfs:
            print(f"\n❌ No PDF files found in: {directory}")
            return
        
        print(f"\n📁 Found {len(pdfs)} PDF(s) in: {directory}")
        print("=" * 55)
        
        results = []
        for i, pdf in enumerate(pdfs, 1):
            pdf_path = os.path.join(directory, pdf)
            print(f"\n[{i}/{len(pdfs)}] {pdf}")
            
            analyzer = PDFXRay(pdf_path)
            report = analyzer.run()
            
            if report:
                analyzer.display_report()
                results.append(report)
                
                if json_mode:
                    analyzer.save_json_report()
        
        # Summary
        print("\n" + "=" * 55)
        print("📊 BATCH SUMMARY")
        print("=" * 55)
        
        critical = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in results if r['risk_level'] == 'LOW')
        
        print(f"   🔴 Critical: {critical}")
        print(f"   🟠 High:     {high}")
        print(f"   🟡 Medium:   {medium}")
        print(f"   🟢 Low:      {low}")
        
    else:
        # Single file analysis
        if not os.path.isfile(target):
            print(f"\n❌ File not found: {target}")
            return
        
        if not target.lower().endswith('.pdf'):
            print(f"\n❌ Not a PDF: {target}")
            return
        
        print(f"\n📄 Target: {os.path.basename(target)}")
        print(f"📏 Size: {os.path.getsize(target):,} bytes")
        print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)
        
        analyzer = PDFXRay(target)
        report = analyzer.run()
        
        if report:
            analyzer.display_report()
            
            if json_mode:
                analyzer.save_json_report()

if __name__ == "__main__":
    main()