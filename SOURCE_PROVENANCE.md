# CryptoFace LattiSense source provenance

This source-only snapshot vendors the exact revisions preserved by the
validated CryptoFace native GPU release. Nested repositories are committed as
ordinary source directories so a clean checkout does not depend on mutable or
unavailable upstream submodule refs.

| Component | Preserved revision | Source directory |
| --- | --- | --- |
| LattiSense | `fbb85da05139af3b6e164fea76ee02f98ace3442` | `/` |
| HEonGPU | `aaf76f94bfb2fca2f3b02ff63bea72fb8d4b1680` | `backends/HEonGPU` |
| HEonGPU GPU-NTT | `c6507e99e12b7cf658cda4a2dadedaad7fdee56b` | `backends/HEonGPU/thirdparty/GPU-NTT` |
| HEonGPU GPU-FFT | `b743607c1173000718ca1f84016fd03093ebb6fc` | `backends/HEonGPU/thirdparty/GPU-FFT` |
| HEonGPU RNGonGPU | `d9aaa6b5d7cc67a2ca307ef9d6203f25cc2458b4` | `backends/HEonGPU/thirdparty/RNGonGPU` |
| RNGonGPU GPU-NTT | `32332ce0f367b7e04612e66ae63da3812fb3b8e3` | `backends/HEonGPU/thirdparty/RNGonGPU/thirdparty/GPU-NTT` |
| Lattigo bridge | `19d1e4edc162d641ebb6b636beda08496a1a070e` | `fhe_ops_lib/lattigo` |

All upstream license files are preserved in their source directories. Build
products (`*.a`, `*.so`, `*.cubin`, `*.ptx`, and build/install directories)
are intentionally excluded from version control.

The validated Blackwell package was built for CUDA architecture 120. The H200
port must be built from this source with CUDA architecture 90 and must pass the
CryptoFace numerical and memory validation gates before it is considered a
validated replacement.
