import copy
import unittest
from decimal import Decimal

from strategy_simulation import (
    build_report,
    calculate_payout_minor,
    production_outcome_cents,
    _random_strategy_target,
    simulate_round_payout,
    validate_artifact,
    validate_known_mean,
)


class StrategySimulationTest(unittest.TestCase):
    def test_known_distribution_recovers_exact_mean_and_rejects_biased_payout(self):
        values = [0, 100, 100, 200]
        self.assertEqual(100, validate_known_mean(values, expected_mean=100, tolerance=0))
        with self.assertRaisesRegex(ValueError, "mean"):
            validate_known_mean([0, 101, 101, 200], expected_mean=100, tolerance=0)

    def test_production_outcome_vectors_and_minor_unit_floor_match(self):
        self.assertEqual(266, production_outcome_cents("0" * 64, "seed-a", "seed-b", "seed-c"))
        self.assertEqual(290, production_outcome_cents("a" * 64, "client-1", "client-2", "client-3"))
        self.assertEqual(124, calculate_payout_minor(101, Decimal("1.2345")))
        self.assertEqual(0, calculate_payout_minor(101, Decimal("0")))

    def test_cashout_requires_a_reachable_step_before_crash_and_respects_stakes(self):
        self.assertEqual((0, False), simulate_round_payout(125, 125, 10000))
        self.assertEqual((12500, True), simulate_round_payout(130, 125, 10000))
        self.assertEqual((0, False), simulate_round_payout(115, 111, 10000))
        self.assertEqual((11500, True), simulate_round_payout(120, 111, 10000))
        for stake in (100, 1000, 10000, 100000):
            self.assertEqual(stake, calculate_payout_minor(stake, Decimal("1.00")))
            self.assertEqual(stake * 100, calculate_payout_minor(stake, Decimal("100.00")))

    def test_random_strategy_target_is_deterministic_and_inside_approved_bounds(self):
        material = b"fixed simulation round material"
        first = _random_strategy_target(material)
        self.assertEqual(first, _random_strategy_target(material))
        self.assertGreaterEqual(first, 110)
        self.assertLessEqual(first, 1000)

    def test_same_seed_reproduces_all_strategy_results_and_provenance(self):
        first = build_report(
            sample_count=1000,
            batch_size=100,
            bootstrap_resamples=50,
            master_seed="20261011",
            commit_hash="test-commit",
        )
        second = build_report(
            sample_count=1000,
            batch_size=100,
            bootstrap_resamples=50,
            master_seed="20261011",
            commit_hash="test-commit",
        )
        self.assertEqual(first, second)
        self.assertEqual(12, len(first["strategies"]))
        self.assertTrue(all(item["sampleCount"] == 1000 for item in first["strategies"]))
        self.assertEqual(12000, first["configuration"]["totalStrategyEvaluations"])
        self.assertEqual("test-commit", first["provenance"]["commitHash"])
        self.assertEqual("1.0.0", first["provenance"]["algorithmVersion"])
        self.assertTrue(first["provenance"]["configurationFingerprint"])

    def test_tampered_commit_config_or_corpus_digest_is_rejected(self):
        report = build_report(
            sample_count=1000,
            batch_size=100,
            bootstrap_resamples=50,
            master_seed="20261011",
            commit_hash="test-commit",
        )
        self.assertTrue(validate_artifact(report, report))
        for field in ("commitHash", "sourceTreeDigest", "algorithmVersion", "configurationFingerprint", "corpusDigest"):
            changed = copy.deepcopy(report)
            changed["provenance"][field] = "tampered"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_artifact(changed, report)
        changed_contents = copy.deepcopy(report)
        changed_contents["strategies"][0]["observed"]["rtp"] += 0.01
        with self.assertRaisesRegex(ValueError, "reportDigest"):
            validate_artifact(changed_contents, report)


if __name__ == "__main__":
    unittest.main()
