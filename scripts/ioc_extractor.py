import re

def extract_iocs(text):
    """Extract common Indicators of Compromise (IOCs) from text."""

    ip_addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    domains = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        text
    )

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    sha256 = re.findall(
        r"\b[A-Fa-f0-9]{64}\b",
        text
    )

    md5 = re.findall(
        r"\b[A-Fa-f0-9]{32}\b",
        text
    )

    return {
        "IP Addresses": ip_addresses,
        "Domains": domains,
        "URLs": urls,
        "SHA256": sha256,
        "MD5": md5,
    }


if __name__ == "__main__":
    
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_path = project_root / "logs" / "sample_sysmon.log"

    sample = log_path.read_text(encoding="utf-8")

    results = extract_iocs(sample)

    for key, value in results.items():
        print(key + ":")
        for item in value:
            print(" -", item)
