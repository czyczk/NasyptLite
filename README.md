# nasypt-lite

Password-based encryption library, CLI, and source generator for .NET, supporting multiple algorithms:

| Algorithm | Default | Cipher | Auth | Standard |
|---|---|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | yes | AES-256-CBC | — | Jasypt 3.x |
| `PBEWithHMACSM3AndSM4_GCM` | — | SM4-GCM | AEAD + HMAC-SM3 key commit | GM/T 0091† |
| `PBEWithHMACSM3AndSM4_CBC` | — | SM4-CBC | Encrypt-then-HMAC-SM3 | GM/T 0091-2020 |

† GCM mode is a modern extension to the PBES2 framework.

Wire formats are **fully cross-compatible** with the Rust [`rasypt-lite`](https://github.com/anomalyco/rasypt-lite) library — encrypt with one, decrypt with the other.

Three projects in this repository:

- **`NasyptLite`** — core library: `Encrypt`, `Decrypt`, `ENC(...)` helpers, secure memory zeroing.
- **`NasyptLite.Cli`** — CLI tool with `--algorithm` / `-a` and `--iterations`.
- **`NasyptLite.SourceGen`** — Roslyn source generator `[NasyptDecrypt]` + `[Encrypted]` for transparent property decryption.

---

## Basic library usage

```xml
<PackageReference Include="NasyptLite" Version="1.0.0" />
```

```csharp
using NasyptLite;

var ciphertext = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, "password", "hello world");
var plaintext = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, "password", ciphertext);
// plaintext == "hello world"
```

The default algorithm is `PBEWithHMACSHA512AndAES_256` for backward compatibility:

```csharp
using NasyptLite;

var ct = Nasypt.Encrypt("pass", "plain");
var pt = Nasypt.Decrypt("pass", ct);
```

### Algorithm defaults

| Algorithm | Iterations | Key size |
|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | 1,000 | 256-bit |
| `PBEWithHMACSM3AndSM4_GCM` | 10,000 | 128-bit |
| `PBEWithHMACSM3AndSM4_CBC` | 10,000 | 128-bit |

Override iterations by passing an explicit `iterations` argument to `EncryptWith` / `DecryptWith`. When `null`, the algorithm-specific default is used automatically.

### ENC(…) helpers

```csharp
// Check if a value is ENC-wrapped
Nasypt.IsEncValue("ENC(base64...)"); // true

// Unwrap and decrypt (throws NasyptException if not wrapped)
var secret = Nasypt.DecryptEnc("ENC(base64...)", "password");

// Try-unwrap pattern (no throw)
if (Nasypt.TryUnwrapEnc(value, out var inner))
    secret = Nasypt.Decrypt("password", inner);
```

---

## CLI

```
nasypt-lite encrypt --input "secret" --password "mypass" --algorithm PBEWithHMACSM3AndSM4_GCM
nasypt-lite decrypt --input "base64..." --password "mypass" --algorithm PBEWithHMACSM3AndSM4_GCM
```

| Flag | Short | Description |
|---|---|---|
| `--algorithm` | `-a`, `--alg` | Algorithm name (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | — | Override PBKDF2 iteration count |
| `--wrap` | — | Wrap output in `ENC(...)` (AES only) |
| `--quiet` | `-q` | Silence password warnings |

See [`src/NasyptLite.Cli/README.md`](src/NasyptLite.Cli/README.md) for detailed usage.

---

## Source generator

```csharp
using NasyptLite;

[NasyptDecrypt]
public partial class AppConfig
{
    public string Username { get; set; }

    [Encrypted]
    public string Password { get; set; }      // string — auto-decrypted

    [Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_GCM")]
    public string? ApiKey { get; set; }        // string? — null-safe, SM4-GCM
}

var cfg = new AppConfig { Password = "ENC(...)", ApiKey = "ENC(...)" };
cfg.DecryptEncFields("mypassword");
// cfg.Password and cfg.ApiKey are now plaintext

cfg.ClearSensitiveFields();
// or just dispose:
using (var cfg = new AppConfig { ... }) { ... } // auto-clears on dispose
```

The source generator adds these methods to any `partial class` marked `[NasyptDecrypt]`:

- `DecryptEncFields(string password)` — walks `[Encrypted]` properties, checks for `ENC(...)` wrapping, and decrypts them in-place.
- `ClearSensitiveFields()` — replaces tagged `string` properties with `string.Empty` and `string?` with `null`.
- `IDisposable` implementation — calls `ClearSensitiveFields()` on dispose.

**Per-field algorithm:** Set `[Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_GCM")]` to use a non-default algorithm. Different properties can use different algorithms.

**Supported property types:** `string` and `string?`. Other types are silently ignored. Only classes with named properties are supported.

See [`src/NasyptLite.SourceGen/README.md`](src/NasyptLite.SourceGen/README.md) for more details.

---

## Publishing

Build a single-file NativeAOT binary (recommended for distribution):

```
dotnet publish src/NasyptLite.Cli -c Release
```

The NativeAOT binary is ~3 MB, self-contained, and starts in ~6 ms. Add `<PublishAot>true</PublishAot>` to the CLI `.csproj` if not already present.

See the [benchmark notes](notes/benchmark.md) for performance comparisons with Rust `rasypt-lite`.

---

## Compatibility

- The default of `PBEWithHMACSHA512AndAES_256` is fully compatible with Jasypt.
- All three algorithms are wire-format compatible with Rust [`rasypt-lite`](https://github.com/anomalyco/rasypt-lite). Tested both directions.
- The SM-based alternatives provide better security but do not exist in Jasypt, so no Jasypt compatibility is claimed for them.

---

## Security

- **SM4-GCM**: Authenticated encryption (AEAD) with 128-bit GCM tag. HMAC-SM3 key commitment over `salt || nonce || ciphertext || tag` defends against partitioning oracle attacks.
- **SM4-CBC**: Encrypt-then-MAC with HMAC-SM3 over `IV || ciphertext`. MAC verified before decryption (constant-time). Separate encryption and MAC keys.
- **Constant-time**: MAC/tag/key-commitment comparisons use a branch-free XOR loop. A single generic error (`DecryptionFailed`) is returned for all decryption failures — no oracle leakage.
- **Key derivation**: PBKDF2 with 1,000 (AES) or 10,000 (SM, matches GM/T 0091-2020) default iterations. Override with `--iterations` for higher counts (600,000 recommended for production). NFC-normalized passwords (Unicode Normalization Form C). Key material zeroed after use via `CryptographicOperations.ZeroMemory`.
- **Salt**: 16 bytes (128-bit) from OS CSPRNG, fresh per encryption. IV/nonce also from OS CSPRNG.
- **Dependencies**: AES uses the .NET BCL (`System.Security.Cryptography`). SM3/SM4 uses [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) (286M+ downloads).

---

## License

MIT
