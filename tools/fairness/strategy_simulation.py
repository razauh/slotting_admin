import argparse
import hashlib
import hmac
import json
import math
import random
import subprocess
from decimal import Decimal, ROUND_FLOOR
from pathlib import Path

from analyze_distribution import cdf_count


ALGORITHM_VERSION = "1.0.0"
RULES_VERSION = "1.0.0"
MULTIPLIER_STEP_CENTS = 5
PAYOUT_CAP_MULTIPLIER = 100
STRATEGIES = (
    ("S01", 110),
    ("S02", 125),
    ("S03", 150),
    ("S04", 200),
    ("S05", 300),
    ("S06", 500),
    ("S07", 1000),
    ("S08", 2000),
    ("S09", 5000),
    ("S10", 10000),
    ("S11", None),
    ("S12", "random"),
)
BOUNDARY_STAKES = (100, 1000, 10000, 100000)
SOURCE_FILES = (
    "src/main/kotlin/com/slotting/admin/gameprovider/AviatorAlgorithmRegistry.kt",
    "src/main/kotlin/com/slotting/admin/gameprovider/IndependentFairnessVerifier.kt",
    "src/main/kotlin/com/slotting/admin/gameprovider/FlightClock.kt",
    "src/main/kotlin/com/slotting/admin/gameprovider/DurableGameWagerAndSettlementService.kt",
    "src/main/kotlin/com/slotting/admin/gameprovider/AviatorRoundLifecycleOrchestrator.kt",
    "tools/fairness/analyze_distribution.py",
    "tools/fairness/strategy_simulation.py",
)


def production_outcome_cents(server_seed, client_seed1, client_seed2, client_seed3):
    combined = server_seed + client_seed1 + client_seed2 + client_seed3
    hashed = hashlib.sha512(combined.encode("utf-8")).hexdigest()
    value = int(hashed[:13], 16)
    domain = 1 << 52
    if value % 100 < 3:
        return 100
    raw_multiplier = float(domain) / (float(domain) - float(value))
    return max(101, math.floor(raw_multiplier * 100.0))


def calculate_payout_minor(stake_minor, multiplier):
    amount = (Decimal(stake_minor) * Decimal(multiplier)).to_integral_value(rounding=ROUND_FLOOR)
    return min(int(amount), stake_minor * PAYOUT_CAP_MULTIPLIER)


def validate_known_mean(values, expected_mean, tolerance):
    if not values:
        raise ValueError("mean cannot be validated for an empty sample")
    actual = sum(values) / len(values)
    if abs(actual - expected_mean) > tolerance:
        raise ValueError(f"mean mismatch: expected {expected_mean}, observed {actual}")
    return actual


def _canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _percentile(values, probability):
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _effective_cashout_cents(target_cents):
    ticks = (target_cents - 100 + MULTIPLIER_STEP_CENTS - 1) // MULTIPLIER_STEP_CENTS
    return 100 + ticks * MULTIPLIER_STEP_CENTS


def _round_payout(outcome_cents, target_cents, stake_minor):
    if target_cents is None:
        return 0, False
    effective_cents = _effective_cashout_cents(target_cents)
    if outcome_cents <= effective_cents:
        return 0, False
    payout = (stake_minor * effective_cents) // 100
    return min(payout, stake_minor * PAYOUT_CAP_MULTIPLIER), True


def simulate_round_payout(outcome_cents, target_cents, stake_minor):
    return _round_payout(outcome_cents, target_cents, stake_minor)


def _new_accumulator():
    return {
        "count": 0,
        "wagerTotal": 0,
        "payoutTotal": 0,
        "winCount": 0,
        "netTotal": 0,
        "netSquareTotal": 0,
        "cumulativeNet": 0,
        "peakNet": 0,
        "maxDrawdown": 0,
        "minPrefixNet": 0,
        "maxPrefixNet": 0,
    }


def _add_observation(accumulator, payout, stake_minor):
    net = payout - stake_minor
    accumulator["count"] += 1
    accumulator["wagerTotal"] += stake_minor
    accumulator["payoutTotal"] += payout
    accumulator["winCount"] += int(payout > 0)
    accumulator["netTotal"] += net
    accumulator["netSquareTotal"] += net * net
    accumulator["cumulativeNet"] += net
    accumulator["peakNet"] = max(accumulator["peakNet"], accumulator["cumulativeNet"])
    accumulator["maxDrawdown"] = max(
        accumulator["maxDrawdown"],
        accumulator["peakNet"] - accumulator["cumulativeNet"],
    )
    accumulator["minPrefixNet"] = min(accumulator["minPrefixNet"], accumulator["cumulativeNet"])
    accumulator["maxPrefixNet"] = max(accumulator["maxPrefixNet"], accumulator["cumulativeNet"])


def _combine_drawdown(blocks):
    offset = 0
    peak = 0
    drawdown = 0
    for block in blocks:
        drawdown = max(drawdown, block["maxDrawdown"], peak - (offset + block["minPrefixNet"]))
        peak = max(peak, offset + block["maxPrefixNet"])
        offset += block["netTotal"]
    return drawdown


def _metrics(blocks):
    count = sum(block["count"] for block in blocks)
    wager = sum(block["wagerTotal"] for block in blocks)
    payout = sum(block["payoutTotal"] for block in blocks)
    wins = sum(block["winCount"] for block in blocks)
    net = sum(block["netTotal"] for block in blocks)
    square_total = sum(block["netSquareTotal"] for block in blocks)
    mean_net = net / count
    variance = max(0.0, square_total / count - mean_net * mean_net)
    rtp = payout / wager
    return {
        "rtp": rtp,
        "houseEdge": 1.0 - rtp,
        "averageNetMinorPerRound": mean_net,
        "cashOutSuccessRate": wins / count,
        "maximumDrawdownMinor": _combine_drawdown(blocks),
        "returnStandardDeviationMinor": math.sqrt(variance),
        "sampleCount": count,
    }


def _bootstrap_intervals(batch_results, bootstrap_resamples, seed_material):
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")
    generator = random.Random(seed)
    metrics = {
        "rtp": [],
        "houseEdge": [],
        "averageNetMinorPerRound": [],
        "cashOutSuccessRate": [],
        "maximumDrawdownMinor": [],
        "returnStandardDeviationMinor": [],
    }
    batch_count = len(batch_results)
    for _ in range(bootstrap_resamples):
        selected = [batch_results[index] for index in generator.choices(range(batch_count), k=batch_count)]
        result = _metrics(selected)
        for name in metrics:
            metrics[name].append(result[name])
    return {
        name: {"lower": _percentile(values, 0.025), "upper": _percentile(values, 0.975)}
        for name, values in metrics.items()
    }


def _theoretical_rtp(targets, stake_minor):
    domain = 1 << 52
    instant_crashes = (domain // 100) * 3 + min(domain % 100, 3)
    result = 0.0
    for target in targets:
        if target is None:
            continue
        effective_cents = _effective_cashout_cents(target)
        payout = min((stake_minor * effective_cents) // 100, stake_minor * PAYOUT_CAP_MULTIPLIER)
        cdf = cdf_count(domain, instant_crashes, effective_cents)
        success_probability = (domain - cdf) / domain
        result += (payout / stake_minor) * success_probability / len(targets)
    return result


def _git_commit():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _source_tree_digest():
    digest = hashlib.sha256()
    for relative_path in SOURCE_FILES:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(Path(relative_path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _replication_seed(master_seed, batch_index):
    return hmac.new(master_seed.encode("utf-8"), f"replication:{batch_index}".encode("utf-8"), hashlib.sha256).digest()


def _round_material(replication_seed, round_id):
    return hmac.new(replication_seed, round_id.encode("utf-8"), hashlib.sha256).digest()


def _random_strategy_target(round_material):
    target_count = 891
    limit = (1 << 256) // target_count * target_count
    attempt = 0
    while True:
        label = b"strategy:S12" if attempt == 0 else f"strategy:S12:retry:{attempt}".encode("utf-8")
        digest = hmac.new(round_material, label, hashlib.sha256).digest()
        value = int.from_bytes(digest, "big")
        if value < limit:
            return 110 + value % target_count
        attempt += 1


def build_report(
    sample_count=1000000,
    batch_size=100000,
    bootstrap_resamples=10000,
    master_seed="20261011",
    commit_hash=None,
    stake_minor=10000,
):
    if sample_count <= 0 or batch_size <= 0 or sample_count % batch_size != 0:
        raise ValueError("sample count must be a positive multiple of batch size")
    if bootstrap_resamples <= 0 or stake_minor not in BOUNDARY_STAKES:
        raise ValueError("bootstrap resamples must be positive and stake must be an approved boundary")
    batch_count = sample_count // batch_size
    batches = {name: [] for name, _ in STRATEGIES}
    corpus = hashlib.sha256()
    replication_seed_hashes = []

    for batch_index in range(batch_count):
        replication_seed = _replication_seed(master_seed, batch_index)
        replication_seed_hashes.append(hashlib.sha256(replication_seed).hexdigest())
        accumulators = {name: _new_accumulator() for name, _ in STRATEGIES}
        for round_index in range(batch_size):
            round_id = f"tc032-r{batch_index:02d}-round:{round_index:06d}"
            round_material = _round_material(replication_seed, round_id)
            server_seed = hmac.new(round_material, b"server-seed", hashlib.sha256).hexdigest()
            client_seeds = tuple(
                hmac.new(round_material, f"client-seed:{index}".encode("utf-8"), hashlib.sha256).hexdigest()
                for index in range(1, 4)
            )
            outcome_cents = production_outcome_cents(server_seed, *client_seeds)
            random_target = _random_strategy_target(round_material)
            corpus.update(f"{outcome_cents}:{random_target}\n".encode("ascii"))
            for name, target in STRATEGIES:
                actual_target = random_target if target == "random" else target
                payout, _ = _round_payout(outcome_cents, actual_target, stake_minor)
                _add_observation(accumulators[name], payout, stake_minor)
        for name in batches:
            batches[name].append(accumulators[name])

    expected_commit = commit_hash if commit_hash is not None else _git_commit()
    config = {
        "strategyCount": len(STRATEGIES),
        "uniqueCrashOutcomes": sample_count,
        "totalStrategyEvaluations": sample_count * len(STRATEGIES),
        "algorithmVersion": ALGORITHM_VERSION,
        "rulesVersion": RULES_VERSION,
        "multiplierStep": "0.0500",
        "payoutRounding": "FLOOR",
        "payoutCapMultiplier": str(PAYOUT_CAP_MULTIPLIER),
        "currency": "PKR",
        "minorUnit": "paisa",
        "stakeMinorUnits": stake_minor,
        "sampleCountPerStrategy": sample_count,
        "batchSize": batch_size,
        "batchCount": batch_count,
        "confidenceLevel": 0.95,
        "bootstrapMethod": "replication-level percentile bootstrap",
        "bootstrapResamples": bootstrap_resamples,
        "masterSeed": str(master_seed),
        "seedDerivation": "HMAC-SHA256(masterSeed, replication:index), HMAC-SHA256(replicationSeed, roundId), separate HMAC-SHA256(roundMaterial, strategy:S12)",
    }
    fingerprint = _canonical_hash(config)
    strategies = []
    for name, target in STRATEGIES:
        if target == "random":
            targets = range(110, 1001)
            target_label = "uniform integer hundredths in [1.10x, 10.00x]"
        elif target is None:
            targets = [None]
            target_label = "never cash out"
        else:
            targets = [target]
            target_label = f"auto cash out at {target / 100:.2f}x"
        batch_metrics = [_metrics([batch]) for batch in batches[name]]
        metrics = _metrics(batches[name])
        ci = _bootstrap_intervals(
            batches[name],
            bootstrap_resamples,
            f"{master_seed}|{name}|{fingerprint}".encode("utf-8"),
        )
        expected_rtp = _theoretical_rtp(targets, stake_minor)
        consistent = ci["rtp"]["lower"] <= expected_rtp <= ci["rtp"]["upper"]
        strategies.append({
            "name": name,
            "rule": target_label,
            "sampleCount": sample_count,
            "expectedRtp": expected_rtp,
            "observed": metrics,
            "confidenceIntervals": ci,
            "replicationStability": {
                "batchCount": batch_count,
                "batchSize": batch_size,
                "rtpStandardDeviation": _sample_std([item["rtp"] for item in batch_metrics]),
                "replications": batch_metrics,
            },
            "rtpModelComparison": "PASS" if consistent else "FAIL",
        })

    boundary_checks = []
    for boundary_stake in BOUNDARY_STAKES:
        for multiplier in (Decimal("1.00"), Decimal("1.10"), Decimal("1.25"), Decimal("1.50"), Decimal("2.00"), Decimal("3.00"), Decimal("5.00"), Decimal("10.00"), Decimal("20.00"), Decimal("50.00"), Decimal("100.00")):
            payout = calculate_payout_minor(boundary_stake, multiplier)
            if payout < 0 or payout > boundary_stake * PAYOUT_CAP_MULTIPLIER:
                raise ArithmeticError("stake boundary payout violates production payout cap")
            boundary_checks.append({
                "stakeMinorUnits": boundary_stake,
                "multiplier": str(multiplier),
                "payoutMinorUnits": payout,
            })

    report = {
        "title": "TC-032 Cash-Out Strategy Simulation",
        "configuration": config,
        "financialControls": {
            "exactCrashBoundary": "cash-out succeeds only when the production crash multiplier is strictly above the first reachable 0.0500x step at or above the selected trigger; a crash transition at equality wins before a cash-out can be accepted",
            "settlementBehavior": "cash-out payout is floored to integer minor units and capped at 100 times stake; never-cash-out returns zero",
            "moneyMovement": "offline calculation only; no ledger, account, payment, or production database is accessed",
            "boundaryStakeChecks": boundary_checks,
        },
        "provenance": {
            "commitHash": expected_commit,
            "sourceTreeDigest": _source_tree_digest(),
            "algorithmVersion": ALGORITHM_VERSION,
            "rulesVersion": RULES_VERSION,
            "configurationFingerprint": fingerprint,
            "corpusDigest": corpus.hexdigest(),
            "masterSeed": str(master_seed),
            "replicationSeedDigests": replication_seed_hashes,
            "rngAlgorithm": "HMAC-SHA256 deterministic streams with production SHA-512 outcome mapping",
        },
        "statisticalMethod": {
            "confidenceLevel": 0.95,
        "interval": f"percentile bootstrap using {bootstrap_resamples} resamples at independent {batch_size}-round replication level",
            "resamplingUnit": "independently seeded batch; all 12 strategies share each batch's crash outcomes",
            "multipleComparisons": "per-strategy 95% intervals; no simultaneous family-wise correction is applied",
            "tailLimitation": "one million rounds may not precisely estimate rare 50x and 100x cash-out events",
        },
        "strategies": strategies,
    }
    report["reportDigest"] = _canonical_hash(report)
    return report


def _sample_std(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))


def validate_artifact(candidate, expected):
    fields = ("commitHash", "sourceTreeDigest", "algorithmVersion", "configurationFingerprint", "corpusDigest")
    for field in fields:
        if candidate.get("provenance", {}).get(field) != expected.get("provenance", {}).get(field):
            raise ValueError(f"{field} mismatch")
    candidate_body = {key: value for key, value in candidate.items() if key != "reportDigest"}
    if candidate.get("reportDigest") != _canonical_hash(candidate_body):
        raise ValueError("reportDigest mismatch")
    if candidate.get("reportDigest") != expected.get("reportDigest"):
        raise ValueError("report contents mismatch")
    return True


def _markdown_report(report):
    rows = [
        "# TC-032 Cash-Out Strategy Simulation",
        "",
        f"Commit: `{report['provenance']['commitHash']}`",
        f"Simulation source digest: `{report['provenance']['sourceTreeDigest']}`",
        f"Algorithm/rules: `{report['provenance']['algorithmVersion']}` / `{report['provenance']['rulesVersion']}`",
        f"Configuration fingerprint: `{report['provenance']['configurationFingerprint']}`",
        f"Outcome corpus digest: `{report['provenance']['corpusDigest']}`",
        f"Seed: `{report['provenance']['masterSeed']}`",
        "",
        "All money values are PKR paisa. This offline simulation performs no ledger or payment operations.",
        "",
        "| Strategy | Rule | Samples | Expected RTP | Observed RTP | 95% interval | House edge | Success rate | Avg net / round | Max drawdown | Model comparison |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for item in report["strategies"]:
        observed = item["observed"]
        ci = item["confidenceIntervals"]["rtp"]
        rows.append(
            f"| {item['name']} | {item['rule']} | {item['sampleCount']} | {item['expectedRtp']:.8f} | "
            f"{observed['rtp']:.8f} | [{ci['lower']:.8f}, {ci['upper']:.8f}] | "
            f"{observed['houseEdge']:.8f} | {observed['cashOutSuccessRate']:.8f} | "
            f"{observed['averageNetMinorPerRound']:.3f} | {observed['maximumDrawdownMinor']} | {item['rtpModelComparison']} |"
        )
    rows.extend([
        "",
        "## Statistical limitations",
        "",
        "Intervals are per strategy and use the ten independently seeded 100,000-round batches as bootstrap units. They are not simultaneous family-wise intervals. Tail-event estimates for 50x and 100x targets may remain imprecise at one million rounds.",
        "",
        "The expected return is calculated from the exact 52-bit outcome distribution and the observed production 1.0.0 outcome, tick, floor, and cap contracts. These offline estimates do not establish ledger, concurrency, idempotency, or live payment behavior.",
        "",
        f"Report digest: `{report['reportDigest']}`",
    ])
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="build/tc032/simulation-report.json")
    parser.add_argument("--markdown", default="build/tc032/simulation-report.md")
    parser.add_argument("--samples", type=int, default=1000000)
    parser.add_argument("--batch-size", type=int, default=100000)
    parser.add_argument("--bootstrap-resamples", type=int, default=10000)
    parser.add_argument("--master-seed", default="20261011")
    parser.add_argument("--commit-hash")
    parser.add_argument("--validate-against")
    args = parser.parse_args()
    if args.validate_against:
        candidate = json.loads(Path(args.manifest).read_text())
        expected = json.loads(Path(args.validate_against).read_text())
        validate_artifact(candidate, expected)
        print(json.dumps({"valid": True, "reportDigest": candidate["reportDigest"]}, sort_keys=True))
        return
    report = build_report(
        sample_count=args.samples,
        batch_size=args.batch_size,
        bootstrap_resamples=args.bootstrap_resamples,
        master_seed=args.master_seed,
        commit_hash=args.commit_hash,
    )
    json_path = Path(args.manifest)
    markdown_path = Path(args.markdown)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(_markdown_report(report))
    print(json.dumps({"manifest": str(json_path), "markdown": str(markdown_path), "reportDigest": report["reportDigest"]}, sort_keys=True))


if __name__ == "__main__":
    main()
