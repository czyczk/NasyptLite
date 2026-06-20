# Benchmark: nasypt-lite vs rasypt-lite

Performance comparison between the .NET NativeAOT (`nasypt-lite`) and Rust
(`rasypt-lite`) CLI tools. Both implement the same wire format and algorithms.

**Test environment:** Linux x86-64, .NET 10.0.108 NativeAOT, Rust 1.92.0 release build.

**Methodology:** 3 warm-up runs + 10 measured runs per data point. Plaintext
stored in temp files (`-i <file>`). All runs with `-q` (quiet mode).
Timing via `time.perf_counter` (Python), includes full process launch + encrypt/decrypt.

---

## Startup latency

Encrypt 16 B plaintext, default AES. Measures process-launch-to-exit time.

| Tool | Mean | Min | Max | vs Rust |
|---|---|---|---|---|
| `rasypt-lite` (Rust) | 2.1 ms | 1.3 ms | 4.2 ms | baseline |
| `nasypt-lite` (JIT) | **62.1 ms** | 55.1 ms | 70.4 ms | 30× slower |
| `nasypt-lite` (NativeAOT) | **6.1 ms** | 3.9 ms | 11.4 ms | 2.9× slower |

NativeAOT eliminates the CLR/JIT startup cost. The remaining ~4 ms gap is native
binary load + BouncyCastle initialization.

---

## Encrypt throughput

| Plaintext | Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|---|
| **1 KB** | Rust | 662 KB/s | 125 KB/s | 110 KB/s |
| | .NET AOT | 165 KB/s | 42 KB/s | 41 KB/s |
| **100 KB** | Rust | **49.7 MB/s** | **12.1 MB/s** | **9.8 MB/s** |
| | .NET AOT | 17.3 MB/s | 3.9 MB/s | 4.1 MB/s |
| **1 MB** | Rust | **594 MB/s** | **94 MB/s** | **96 MB/s** |
| | .NET AOT | 146 MB/s | 42 MB/s | 43 MB/s |

At larger plaintext sizes, startup overhead becomes negligible and the
throughput plateaus at the raw crypto speed:

| Algorithm | Rust | .NET AOT | Rust advantage |
|---|---|---|---|
| AES-256-CBC | 594 MB/s | 146 MB/s | 4.1× |
| SM4-GCM | 94 MB/s | 42 MB/s | 2.2× |
| SM4-CBC | 96 MB/s | 43 MB/s | 2.2× |

The AES gap is larger because Rust's `aes` crate uses AES-NI hardware
instructions. .NET's `Aes.Create()` also uses AES-NI, but BouncyCastle's
`SM4Engine` is a managed (non-accelerated) implementation — SM4 has no
widespread hardware acceleration on x86-64.

---

## Decrypt throughput

| Plaintext | Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|---|
| **1 MB** | Rust | **513 MB/s** | **110 MB/s** | **111 MB/s** |
| | .NET AOT | 142 MB/s | 48 MB/s | 46 MB/s |

Decrypt follows the same pattern as encrypt. The SM4-GCM decrypt is slightly
slower than encrypt in Rust (GCM tag verification adds a GHASH pass), but the
difference is within measurement noise for AOT.

---

## PBKDF2 iteration scaling

Encrypt 1 KB plaintext, default AES. Higher iteration counts stress the key
derivation independently of the cipher.

| Iterations | Rust | .NET AOT | .NET AOT (JIT) | Winner |
|---|---|---|---|---|
| 1,000 | 2.3 ms | 6.7 ms | 61.2 ms | Rust |
| 10,000 | 7.7 ms | 11.2 ms | 70.9 ms | Rust (1.5×) |
| 100,000 | 56.5 ms | **52.2 ms** | 105.6 ms | **AOT by 8%** |

At 100,000 iterations, NativeAOT overtakes Rust. .NET's `Rfc2898DeriveBytes`
with SHA-512 is highly optimized (SIMD-accelerated HMAC-SHA512 via
`System.Security.Cryptography`), while Rust's `pbkdf2_hmac::<Sha512>` does not
use SHA-512-specific SIMD. This only matters at very high iteration counts.

---

## JIT vs NativeAOT comparison

To isolate the JIT overhead, compare the same .NET build with and without
NativeAOT (both encrypt 1 MB, AES):

| Metric | JIT | NativeAOT | Improvement |
|---|---|---|---|
| Startup | 62.1 ms | 6.1 ms | **10.2×** |
| Encrypt 1 MB | 14.9 MB/s | 145.9 MB/s | **9.8×** |
| Decrypt 1 MB | 16.5 MB/s | 142.0 MB/s | **8.6×** |
| Binary size | 5.0 MB† | 3.0 MB | 1.7× smaller |

† Framework-dependent single-file (requires .NET runtime installed).

The JIT numbers are dominated by cold-start compilation. Once JIT-compiled, the
crypto throughput is similar, but every CLI invocation pays the JIT cost.
NativeAOT compiles once at build time and starts instantly.

---

## Binary size

| Build | Size | Self-contained |
|---|---|---|
| Rust release | ~2.5 MB | Yes |
| .NET NativeAOT | 3.0 MB | Yes |
| .NET JIT (framework-dep) | 5.0 MB | No (needs .NET 10) |
| .NET JIT (self-contained) | ~65 MB | Yes |

---

## Summary

- **Startup:** NativeAOT bridges most of the gap — 6 ms vs Rust's 2 ms.
- **AES crypto:** Rust is ~4× faster (AES-NI in both, but Rust avoids managed interop overhead).
- **SM4 crypto:** Rust is ~2.2× faster (native vs BouncyCastle managed).
- **PBKDF2 at scale:** NativeAOT is slightly faster at 100k+ iterations (.NET's SIMD SHA-512 beats Rust's generic implementation).
- **For CLI use:** NativeAOT is the recommended build. The 6 ms startup is fast enough for interactive use and scripting.
- **For server/library use:** The library code path (without process launch) is comparable — both the JIT and AOT paths use the same BCL/BouncyCastle crypto primitives once loaded.
