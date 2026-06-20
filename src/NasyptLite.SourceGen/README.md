# NasyptLite.SourceGen

Roslyn incremental source generator for classes with encrypted properties.

Add `[NasyptDecrypt]` to a `partial class` and `[Encrypted]` to `string` / `string?` properties. At compile time, the source generator produces a partial class with:

- `DecryptEncFields(string password)` — walks `[Encrypted]` properties, checks for `ENC(...)` wrapping, and decrypts them in-place. Throws `NasyptException` on failure.
- `ClearSensitiveFields()` — replaces tagged `string` properties with `string.Empty` and `string?` with `null`.
- `IDisposable` implementation — calls `ClearSensitiveFields()` on dispose so secrets are cleared when the object goes out of scope.

**Algorithm note:** The default is `PBEWithHMACSHA512AndAES_256`. Specify a different algorithm per property with `[Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_GCM")]`. The value must be a valid `NasyptLite.Algorithm` name. Different properties can use different algorithms.

## Installation

```xml
<PackageReference Include="NasyptLite.SourceGen" Version="1.0.0"
                  OutputItemType="Analyzer" ReferenceOutputAssembly="false" />
```

Also reference the core library:

```xml
<PackageReference Include="NasyptLite" Version="1.0.0" />
```

## Example

```csharp
using NasyptLite;

[NasyptDecrypt]
public partial class AppConfig
{
    public string Host { get; set; }

    // AES-256-CBC (default)
    [Encrypted]
    public string DbPassword { get; set; }

    // Nullable — only processed when non-null
    [Encrypted]
    public string? OptionalSecret { get; set; }

    // SM4-GCM per-field override
    [Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_GCM")]
    public string ApiKey { get; set; }
}

var cfg = new AppConfig
{
    Host = "localhost",
    DbPassword = "ENC(base64...)",
    OptionalSecret = null,
    ApiKey = "ENC(base64...)",
};

cfg.DecryptEncFields("mypassword");
// cfg.DbPassword and cfg.ApiKey are now plaintext
// cfg.OptionalSecret remains null (skipped)

// Manual clearing
cfg.ClearSensitiveFields();

// Or automatic via Dispose
using (var cfg2 = new AppConfig { DbPassword = "ENC(...)" })
{
    cfg2.DecryptEncFields("pw");
} // DbPassword cleared here
```

## Supported property types

`string` and `string?` (`Nullable<string>`). Other types are silently ignored.
Only classes with named properties are supported (no positional records, no fields).

## How it works

The source generator runs at compile time via the Roslyn analyzer infrastructure.
It scans classes marked `[NasyptDecrypt]`, finds properties with `[Encrypted]`,
and emits a partial class containing the decryption, clearing, and dispose logic.

The generated code calls into `NasyptLite.Nasypt` — make sure the core library
is referenced in your project.
