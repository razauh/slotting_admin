# Fairness property corpus

`golden-vectors.csv` stores cross-language reference inputs and exact two-decimal outcomes for algorithm version `1.0.0`. The fields are server seed, client seeds one through three, and expected multiplier. Seeds are UTF-8 strings, matching the verifier contract.

The distribution harness evaluates 10,000 fixed inputs. For sample index `i`, each seed is a stable string containing `i`; no wall-clock or random source is used. The instant-crash bound is 1.5% to 4.5%, centered on the formula's 3% modulus rate. Its width is intentionally conservative for a reusable regression guard. The two-times cashout return is estimated as `2 × wins / samples`; house edge is `1 − return`. Its accepted range is 0% to 6%, a three percentage point tolerance around the formula's nominal 3% edge that allows for finite sample variation. These bounds and the sample size are shared by future fairness tests.

The verify helper first compares SHA-256 of the revealed server seed with the published commitment, then recomputes the outcome with the registered formula version and compares numeric multiplier values. Database persistence is unnecessary for these pure deterministic checks.
