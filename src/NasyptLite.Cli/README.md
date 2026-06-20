# nasypt-lite CLI

Command-line tool wrapping `NasyptLite` for encrypting/decrypting strings with password-based encryption.

## Installation

```sh
dotnet publish src/NasyptLite.Cli -c Release
```

The binary is at `src/NasyptLite.Cli/bin/Release/net10.0/linux-x64/publish/NasyptLite.Cli`.
Copy it anywhere on your `$PATH`. The NativeAOT binary is self-contained — no .NET runtime required.

## Usage

```
nasypt-lite <COMMAND>

Commands:
  encrypt    Encrypt a plaintext value.
  decrypt    Decrypt a ciphertext or ENC(...)-wrapped value.

Options:
  -?, -h, --help  Show help and usage information
  --version       Show version information
```

### Encrypt

```
nasypt-lite encrypt --input <INPUT> --password <PASSWORD> [OPTIONS]
```

| Flag | Description |
|---|---|
| `-i`, `--input` | Plaintext to encrypt |
| `-p`, `--password` | Password for key derivation |
| `-a`, `--algorithm`, `--alg` | Algorithm (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | Override PBKDF2 iteration count |
| `--wrap` | Wrap output in `ENC(...)` (AES only) |
| `-q`, `--quiet` | Suppress password-strength warnings |

Valid algorithms: `PBEWithHMACSHA512AndAES_256`, `PBEWithHMACSM3AndSM4_GCM`, `PBEWithHMACSM3AndSM4_CBC`.

### Decrypt

```
nasypt-lite decrypt --input <INPUT> --password <PASSWORD> [OPTIONS]
```

Same flags as encrypt (except `--wrap`). The `--algorithm` and `--iterations` must match what was used during encryption. When the input is wrapped in `ENC(...)`, the AES default algorithm auto-detects and unwraps it.

## Examples

```sh
# AES-256-CBC (default, Jasypt-compatible)
nasypt-lite encrypt -i "top secret" -p "mypassword"
nasypt-lite decrypt -i "base64output..." -p "mypassword"

# SM4-GCM (authenticated encryption)
nasypt-lite encrypt -i "hello" -p "mypass" -a PBEWithHMACSM3AndSM4_GCM
nasypt-lite decrypt -i "base64output..." -p "mypass" -a PBEWithHMACSM3AndSM4_GCM

# SM4-CBC (encrypt-then-MAC)
nasypt-lite encrypt -i "hello" -p "mypass" -a PBEWithHMACSM3AndSM4_CBC
nasypt-lite decrypt -i "base64output..." -p "mypass" -a PBEWithHMACSM3AndSM4_CBC

# Custom iteration count (recommended 600,000 for production)
nasypt-lite encrypt -i "secret" -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000
nasypt-lite decrypt -i "base64output..." -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000

# ENC(...) wrapping (AES only, for Jasypt/Spring Boot interop)
nasypt-lite encrypt -i "secret" -p "mypass" --wrap
# Output: ENC(base64...)

# Auto-detect and decrypt ENC(...) values
nasypt-lite decrypt -i "ENC(base64...)" -p "mypass"
```

## Password warnings

Passwords shorter than 8 Unicode scalar values produce a warning to stderr:

```
Warning: password length is below the recommended 8 characters; continuing anyway. Use --quiet to suppress this warning.
```

Suppress with `--quiet` / `-q`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Encryption or decryption failed |

## Cross-compatibility

All three algorithms are wire-format compatible with Rust
[`rasypt-lite`](https://github.com/anomalyco/rasypt-lite). Encrypt with one,
decrypt with the other — no flags or conversion needed.

## Performance

NativeAOT publish is recommended for CLI use. Approximate timings (encrypt 1 KB, Linux x86-64):

| Algorithm | Time (NativeAOT) | Time (Rust) |
|---|---|---|
| AES-256-CBC | ~6 ms | ~2 ms |
| SM4-GCM | ~24 ms | ~9 ms |
| SM4-CBC | ~25 ms | ~9 ms |

PBKDF2 iterations affect derivation time:

| Iterations | NativeAOT | Rust |
|---|---|---|
| 1,000 | ~7 ms | ~2 ms |
| 10,000 | ~11 ms | ~8 ms |
| 100,000 | ~52 ms | ~57 ms |

See [`notes/benchmark.md`](../../notes/benchmark.md) for the full benchmark with JIT vs NativeAOT vs Rust comparisons.
