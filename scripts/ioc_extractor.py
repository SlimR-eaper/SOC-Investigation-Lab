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
def calculate_priority(results):
    total_iocs = 0

    for items in results.values():
        total_iocs += len(set(items))

    if total_iocs == 0:
        return "LOW"
    elif total_iocs <= 3:
        return "MEDIUM"
    else:
        return "HIGH"
    
def generate_report(results):
    print("=" * 40)
    print("SOC Investigation Report")
    print("=" * 40)

    priority = calculate_priority(results)
    print(f"Investigation Priority: {priority}")

    print("\nIOC Statistics")
    print("-" * 40)

    for category, items in results.items():
        unique_items = set(items)
        print(f"{category}: {len(unique_items)}")

    for category, items in results.items():
        print(f"\n{category}:")

        unique_items = sorted(set(items))

        if unique_items:
            for item in unique_items:
                print(f" - {item}")
        else:
            print(" - None found")

if __name__ == "__main__":
    
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_path = project_root / "logs" / "sample_sysmon.log"

    sample = log_path.read_text(encoding="utf-8")

    results = extract_iocs(sample)

    generate_report(results)