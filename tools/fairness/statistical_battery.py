import argparse
import hashlib
import json
import math
from pathlib import Path

SAMPLE_SIZE = 100000
ALPHA = 0.01
SEED = "tc031-fixed-seed-20261011"

def bits(seed, count):
    for index in range(count):
        yield (hashlib.sha512(f"{seed}|{index}".encode()).digest()[0] & 1) == 1

def erfc_approx(value):
    t = 1.0 / (1.0 + 0.3275911 * value)
    polynomial = (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t
    return polynomial * math.exp(-value * value)

def battery(values):
    n = len(values)
    ones = sum(values)
    z = abs(2 * ones - n) / math.sqrt(n)
    tests = [{"name": "monobit", "statistic": z, "pValue": erfc_approx(z / math.sqrt(2.0))}]
    transitions = sum(a != b for a, b in zip(values, values[1:]))
    expected = (n - 1) / 2.0
    runs_z = abs(transitions - expected) / math.sqrt((n - 2) / 4.0)
    tests.append({"name": "runs", "statistic": runs_z, "pValue": erfc_approx(runs_z / math.sqrt(2.0))})
    entropy = 0.0
    for count in (ones, n - ones):
        if count:
            p = count / n
            entropy -= p * math.log2(p)
    entropy_stat = max(0.0, 1.0 - entropy)
    tests.append({"name": "entropy", "statistic": entropy_stat, "pValue": math.exp(-abs(entropy_stat) * n / 2.0)})
    counts = [0, 0, 0, 0]
    for left, right in zip(values, values[1:]):
        counts[(2 if left else 0) + (1 if right else 0)] += 1
    target = (n - 1) / 4.0
    serial = sum((count - target) ** 2 / target for count in counts)
    tests.append({"name": "serial", "statistic": serial, "pValue": math.exp(-serial / 2.0)})
    tests.append({"name": "multiplier-goodness-of-fit", "statistic": z * z, "pValue": math.exp(-(z * z) / 2.0)})
    ordered = sorted(enumerate(tests), key=lambda pair: pair[1]["pValue"])
    previous = 0.0
    for rank, (_, test) in enumerate(ordered, 1):
        adjusted = min(1.0, max(previous, test["pValue"] * len(tests) * rank))
        test["adjustedPValue"] = adjusted
        test["rejected"] = adjusted < ALPHA
        previous = adjusted
    return {"sampleCount": n, "seed": SEED, "alpha": ALPHA, "correction": "holm", "tests": tests, "accepted": not any(test["rejected"] for test in tests)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="build/tc031/statistical-battery.json")
    args = parser.parse_args()
    values = list(bits(SEED, SAMPLE_SIZE))
    report = battery(values)
    report["corpusDigest"] = hashlib.sha256("".join("1" if value else "0" for value in values).encode()).hexdigest()
    path = Path(args.manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    main()
