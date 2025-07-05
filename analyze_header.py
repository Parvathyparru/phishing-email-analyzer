def analyze_email_header(header_text):
    print("\n--- PHISHING HEADER ANALYSIS ---\n")
    
    suspicious = False

    lines = header_text.split('\n')
    for line in lines:
        if "From:" in line:
            print("[Sender] " + line.strip())
        if "Return-Path:" in line:
            print("[Return Path] " + line.strip())
        if "spf=" in line.lower():
            print("[SPF Check] " + line.strip())
            if "fail" in line.lower():
                suspicious = True
        if "dkim=" in line.lower():
            print("[DKIM Check] " + line.strip())
            if "fail" in line.lower():
                suspicious = True
        if "dmarc=" in line.lower():
            print("[DMARC Check] " + line.strip())
            if "fail" in line.lower():
                suspicious = True

    if suspicious:
        print("\n⚠️  Warning: Suspicious email header detected!")
    else:
        print("\n✅ Email header appears safe.")

if __name__ == "__main__":
    with open("sample_header.txt", "r") as file:
        raw_header = file.read()
        analyze_email_header(raw_header)
