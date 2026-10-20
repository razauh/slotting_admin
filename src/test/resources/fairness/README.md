# Fairness property corpus

`golden-vectors.csv` stores cross-language reference inputs and exact two-decimal outcomes for algorithm version `1.0.0`. The fields are server seed, client seeds one through three, and expected multiplier. Seeds are UTF-8 strings, matching the verifier contract.

For integer-only verification, let `e = 2^52`. Concatenate the four non-empty UTF-8 seeds in the listed order, calculate SHA-512, and parse the first 13 hexadecimal characters as the unsigned integer `h`. If `h mod 100 < 3`, the result is `1.00`. Otherwise calculate `cents = max(101, floor((100 × e) / (e − h)))` using integer division and report `cents / 100` with exactly two decimal places. The largest numerator is `450359962737049600`, which fits in a signed 64-bit integer. The draw range is `0 ≤ h < e`.

The test-only integer reference checks the existing production formula against each vector while leaving the production implementation unchanged. Boundary checks pin the instant-crash classes `0`, `1`, and `2`, the first non-instant class, the `1.01` floor, and the maximum 52-bit draw. These vectors and boundary checks apply to version `1.0.0`; each registered algorithm version must publish its own vector corpus.

The distribution harness evaluates 10,000 fixed inputs. For sample index `i`, each seed is a stable string containing `i`; no wall-clock or random source is used. The instant-crash bound is 1.5% to 4.5%, centered on the formula's 3% modulus rate. Its width is intentionally conservative for a reusable regression guard. The two-times cashout return is estimated as `2 × wins / samples`; house edge is `1 − return`. Its accepted range is 0% to 6%, a three percentage point tolerance around the formula's nominal 3% edge that allows for finite sample variation. These bounds and the sample size are shared by future fairness tests.

The verify helper first compares SHA-256 of the revealed server seed with the published commitment, then recomputes the outcome with the registered formula version and compares numeric multiplier values. Database persistence is unnecessary for these pure deterministic checks.
