import argparse
import json
import math
from decimal import Decimal, getcontext
from pathlib import Path

getcontext().prec = 40

def residue_count(limit, modulus=100, residues=3):
    q, r = divmod(limit, modulus)
    return q * residues + min(r, residues)

def cdf_count(domain, instant, cents):
    if cents < 100:
        return 0
    if cents == 100:
        return instant
    max_h = domain - (100 * domain // (cents + 1) + 1)
    if max_h < 0:
        return instant
    bounded = min(max_h + 1, domain)
    return bounded + instant - residue_count(bounded)

def report():
    domain = 1 << 52
    instant = (domain // 100) * 3 + min(domain % 100, 3)
    maximum = 100 * domain
    return {
        "algorithmVersion": "1.0.0",
        "domainSize": str(domain),
        "countedMass": str(domain),
        "instantCrashCount": str(instant),
        "instantCrashProbability": f"{instant}/{domain}",
        "minimum": "1.00",
        "maximum": str(maximum),
        "cdfAt1.01": f"{cdf_count(domain, instant, 101)}/{domain}",
        "meanApproximation": str(Decimal(domain.bit_length() - 1) + Decimal("0.5772156649015329")),
        "method": "exact integer boundary counting with rational mass",
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--algorithm-version", default="1.0.0")
    parser.add_argument("--json", default="build/tc030/distribution.json")
    parser.add_argument("--markdown", default="build/tc030/distribution.md")
    args = parser.parse_args()
    if args.algorithm_version != "1.0.0":
        raise SystemExit("unsupported algorithm version")
    result = report()
    json_path = Path(args.json)
    markdown_path = Path(args.markdown)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    rows = ["# Exact multiplier distribution", "", "| Metric | Value |", "|---|---|"]
    rows.extend(f"| {key} | {value} |" for key, value in result.items())
    markdown_path.write_text("\n".join(rows) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
