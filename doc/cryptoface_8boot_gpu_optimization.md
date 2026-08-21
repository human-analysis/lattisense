# CryptoFace eight-bootstrap GPU source recovery

Date: 2026-07-22

This note records the source-built runtime recovery performed against the
immutable reproduction in `../latti-ai-8boot-multigpu-repro`.

## Revisions

- Correct reconstructed baseline: `8f0c0bfb98c6157ee099b872889dfc7ffe1a9545`
- Optimized makespan runtime: `e0b5fa9eee2e733b59285a3a16eaa4510a0047ba`
- HEonGPU: `6e3465619411bb0fc49449239c9be6a4484949611`
- Lattigo: `4e11871dc8842bfae5bc1f02319c8d27b69b4bed`
- Optimized `build-opt/liblattisense.so` SHA-256:
  `7b385ff6ae190b534b37c9d99f9b2bdd7634e567bff1e88a9c2c8b7a799d0d21`

The immutable frozen reproduction remains at commit `5cb6e12`; it was not
modified during this work.

## Profile diagnosis

Nsight Systems 2025.3.2 captured two queued images from the correct baseline.
Each image executed exactly 340,587 kernels, matching the frozen fast trace.
The arithmetic and transfer volume had not increased, but scheduling stretched
the GPU activity across much longer spans.

| Metric | Frozen fast trace | Source request 1 | Source request 2 |
|---|---:|---:|---:|
| GPU activity span | 15.050 s | 31.308 s | 28.426 s |
| GPU busy union | 9.858 s | 8.564 s | 8.597 s |
| GPU busy percentage | 65.5% | 27.4% | 30.2% |
| Kernel launches | 340,587 | 340,587 | 340,587 |
| Kernel-duration sum | 9.280 s | 7.955 s | 8.081 s |
| Memory copies | 64,286 | 64,287 | 64,273 |
| Transferred data | 65.481 GiB | 65.488 GiB | 65.488 GiB |
| Event synchronizations | 47,513 | 47,509 | 47,515 |

The source trace spent 57-60% of idle time in 0.1-1 ms gaps, compared with
28.4% in the frozen trace. Stream topology and per-image CUDA work counts were
otherwise equivalent.

The reconstructed GPU task was loading the graph through the
`MEMORY_FIRST` default. The frozen source anchor and the previously validated
four-bootstrap recovery used `MAKESPAN_FIRST`. The optimized revision makes
that policy explicit for `FheGpuTask`, without changing arithmetic, bootstrap
placement, streams, parameters, or convolution.

## Correctness and latency gate

One persistent worker processed both images of LFW pair 0 on a 96 GiB RTX PRO
6000 Blackwell. The task retained eight physical bootstraps.

| Metric | Image 1 | Image 2 |
|---|---:|---:|
| Reported encrypted inference | 15.182 s | 14.713 s |
| Queued request wall time | 16.948 s | 16.236 s |
| Relative L2 versus frozen reference | 0.019190 | 0.020056 |
| Maximum absolute error | 0.003771 | 0.003555 |
| Embedding norm | 0.998271 | 0.998848 |

Pair cosine was `0.5227127755`. All 256 values in both embeddings were finite,
and both relative-L2 results passed the `0.03` acceptance threshold.

A contemporaneous frozen-runtime control on another free GPU reported 18.010 s
and 15.996 s for the two images. This confirms that the source scheduler fix
removed the reconstruction regression under the same host load.

## Full 128-pair multi-GPU gate

The optimized source subsequently processed all 128 LFW pairs (256 encrypted
images) with one persistent worker on each of physical GPUs 1, 2, and 3. The
task, input subset, batch executable, and companion libraries came from the
immutable reproduction; only `liblattisense.so` was replaced by the optimized
source build.

| Metric | Optimized source | Frozen reference |
|---|---:|---:|
| Processing time | 1372.047 s | 1383.503 s |
| Mean encrypted inference/image | 14.294 s | 14.448 s |
| Median encrypted inference/image | 13.995 s | 14.221 s |
| P95 encrypted inference/image | 16.074 s | 15.785 s |
| P99 encrypted inference/image | 21.035 s | 19.734 s |
| Maximum encrypted inference/image | 21.679 s | 23.511 s |
| Mean queued wall time/image | 16.024 s | 16.178 s |
| Aggregate pair interval | 10.719 s | 10.809 s |
| Image throughput | 0.186582 images/s | 0.185038 images/s |
| Worker image balance | 86 / 85 / 85 | 87 / 85 / 84 |

Mean encrypted inference improved by 0.154 seconds (1.07%), mean queued wall
time improved by 0.153 seconds (0.95%), and total processing improved by 11.456
seconds (0.83%). Tail latency was mixed: P95 and P99 were higher, while the
maximum was lower. This is one full run of each build, so the small mean
difference should be treated as performance parity with a modest favorable
point estimate rather than a statistically established speedup.

All 256 optimized embeddings were finite. Compared image-by-image with the
frozen output, relative L2 had mean `0.020198`, P95 `0.024307`, and maximum
`0.027118`; every image passed the `0.03` gate. Global maximum absolute error
was `0.006790`. Absolute cosine difference had mean `0.001613` and maximum
`0.007791`. Mean norm difference was `0.000348`, with maximum `0.004224`.

Peak sampled GPU memory was 89,607 MiB for the source build versus 87,962 MiB
for the frozen run. Worker startup times were 302.31, 311.77, and 314.80
seconds. Result checksums were:

- Metrics JSON: `2c174d329145422ca0045b5d632309f520990db4df7aa5387e1bedb1a51695df`
- Embeddings NPZ: `86abe17e63f3ddc6803a8c038f94019854f669a650c1a0bb872e49446616adea`

The corresponding artifacts are preserved under `doc/benchmarks/` as
`cryptoface_8boot_makespan_128pairs_metrics.json` and
`cryptoface_8boot_makespan_128pairs_embeddings.npz`.

## Remaining performance work

The optimized source has recovered the frozen latency envelope. It still
launches roughly 340,000 kernels, performs roughly 64,000 copies, and creates
or synchronizes roughly 47,500 events per image. Further work should preserve
the explicit makespan policy and proceed one gated change at a time: persistent
execution state and immutable plaintext residency, event pooling/reclamation,
then CUDA Graph or kernel-fusion experiments.
