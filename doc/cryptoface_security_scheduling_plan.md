# CryptoFace eight-bootstrap security and GPU scheduling plan

Date: 2026-07-22

## Preserved baseline

- Immutable reference: `../lattisense-8boot-opt`, branch `codex/8boot-gpu-opt`
- Reference commit: `f2293f910afb9f8b5242f918a206f0ddb7e7ab12`
- Reference runtime SHA-256: `7b385ff6ae190b534b37c9d99f9b2bdd7634e567bff1e88a9c2c8b7a799d0d21`
- Experiment tree: `../lattisense-8boot-security-sched`
- Experiment branch: `codex/8boot-security-scheduling`

The experiment tree started byte-identical to the preserved runtime. Parameter
and scheduler experiments must be made only in the experiment tree, one change
at a time.

## Acceptance gates

Every candidate must satisfy all of the following:

- At least 128 bits under the calibrated classical estimator convention used
  by the HE Standard v2 reference point.
- Eight physical bootstraps per encrypted image.
- All 256 embedding values finite.
- Relative L2 error at most `0.03` versus the preserved reference.
- Maximum absolute embedding error at most `0.01`.
- Repeated inference runs to detect nondeterministic arithmetic failures.
- No regression in mean inference latency, multi-GPU makespan, or peak memory
  unless explicitly accepted for a later compensating experiment.

## TODO

- [x] Create an isolated experiment tree and verify its starting runtime hash.
- [x] Inventory the active Q/P chain, secret distributions, and error sigma.
- [x] Pin and calibrate the official lattice estimator against the HE Standard
  v2 `N=65536`, `logQ=1747` reference.
- [x] Estimate the exact active main-secret and bootstrap-ephemeral instances.
- [ ] Produce and compile the smallest practical parameter change that clears
  the 128-bit classical gate with at least one bit of estimator margin.
- [ ] Run repeated layer/inference correctness gates on that parameter set.
- [ ] Run single-image and 128-pair multi-GPU latency gates on the accepted
  secure parameter set.
- [ ] Re-profile kernels, copies, synchronizations, GPU busy time, and idle-gap
  distributions using the accepted secure set as the new baseline.
- [ ] Prototype fixed-DAG/static scheduling changes one at a time.
- [ ] Evaluate selective immutable-plaintext residency within the GPU memory
  budget.
- [ ] Evaluate CUDA Graph capture for repeatable blocks.
- [ ] Prototype targeted NTT/key-switch fusion only after the lower-risk
  scheduling experiments.
- [ ] Run the final 128-pair gate and preserve the winning source, runtime,
  metrics, embeddings, and checksums in a clean commit.

## Exact active security instance

- Ring degree: `N=65536`
- Q primes: 32, `log2(Q)=1592.999991...`
- P primes: 3, `log2(P)=183.000000...`
- Evaluation-key modulus: `log2(QP)=1775.999991...`
- Main secret: fixed Hamming weight 192 with independently random signs
- Error: discrete Gaussian with sigma 3.2
- Bootstrap ephemeral secret: fixed Hamming weight 32
- Ephemeral-secret exposure modulus: `Q0*P`, approximately 238 bits

The main relinearization, rotation, and switching keys expose RLWE samples over
the full QP basis, so QP—not Q alone—is the relevant maximum modulus. The
dense-to-sparse bootstrap switching key encrypts under the H=32 secret only at
Q0 and full P.

## Estimator method and calibration

Estimator: `malb/lattice-estimator` commit
`3e48ef421ec256afddb3e7d2249a77eab6e9ba12`, running under SageMath 10.9.
The reproducible driver is `tools/cryptoface_security_estimate.py`.

Example invocation after creating a Sage environment and checking out the
pinned estimator revision:

```bash
PYTHONPATH=/path/to/lattice-estimator \
  /path/to/sage-environment/bin/python \
  tools/cryptoface_security_estimate.py \
  /path/to/model/server/mega_ag.json --case active
```

The model uses unlimited samples (`m=infinity`), matching the estimator's HE
Standard instances. A fixed-weight secret with independent random signs is
approximated by an exactly balanced sparse ternary secret. This conditions on a
smaller, balanced subset of the implementation distribution and is therefore a
conservative approximation for secret support.

The estimator's default MATZOV word-operation model reproduces the named HE
Standard v2 128-bit point: the lowest attack for `N=65536`, dense ternary,
`logQ=1747`, and sigma 3.2 is approximately 128.0 bits. The rough/Core-SVP
helper reports only about 94 bits for the same reference and must not be labeled
as the standard's classical bit-security value.

| Instance | log2 modulus | Lowest default classical estimate | Gate |
|---|---:|---:|---|
| HE Standard v2 dense reference | 1747 | 128.0 | calibration |
| Active main H=192, QP | 1776 | 125.7 | fail |
| Remove one 46-bit Q prime | 1730 | 129.0 | pass estimate |
| Remove one 61-bit P prime | 1715 | 130.2 | pass estimate |
| Lattigo sparse H=192 reference family | 1546 | 145.1 | pass estimate |

The active parameters therefore narrowly miss the requested 128-bit classical
target. Removing one 46-bit residual Q prime is the preferred candidate because
it both restores estimated security and removes an RNS limb from portions of
the online circuit. It is viable only if the layer schedule can operate with a
bootstrap output level of 15 instead of 16. Removing one P prime is the fallback
security candidate, but it can increase Q/P decomposition work and must be
benchmarked rather than assumed faster.

For sensitivity only, the ADPS16 quantum Core-SVP model reports approximately
82.9 bits for the active set and 86.1 bits after removing one Q prime. These are
not directly comparable to the calibrated default classical numbers. A
requirement of 128 quantum Core-SVP bits would also reject the HE Standard
classical-128 reference and would require a substantially smaller modulus or a
larger ring.

## GPU scheduling workstream

The accepted secure parameter set becomes the scheduling baseline. The current
profile executes about 340,587 kernels, 64,286 copies, and 47,513 event
synchronizations per image. Summed kernel time is roughly 9.3 seconds within a
14-15 second inference, leaving several seconds in launch, dependency, copy,
and synchronization gaps.

Scheduling experiments will proceed in this order:

1. Reconstruct a per-operation timeline and classify host launch gaps.
2. Precompute a static schedule for the fixed inference DAG and remove repeated
   runtime dependency decisions where possible.
3. Keep selected hot immutable plaintexts resident on the GPU without exceeding
   the validated memory budget.
4. Capture repeatable graph blocks with CUDA Graphs.
5. Fuse only the highest-frequency NTT/key-switch sequences whose boundaries
   are proven by the profile.

Extra streams and event-cleanup variants already failed to improve latency and
are not priority experiments.
