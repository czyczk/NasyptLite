namespace NasyptLite;

/// <summary>Supported password-based encryption algorithms.</summary>
public enum Algorithm
{
    /// <summary>PBEWithHMACSHA512AndAES_256 — Jasypt-compatible, AES-256-CBC with PBKDF2-HMAC-SHA512.</summary>
    PBEWithHMACSHA512AndAES_256,
    /// <summary>PBEWithHMACSM3AndSM4_GCM — SM4-GCM AEAD with HMAC-SM3 key commitment.</summary>
    PBEWithHMACSM3AndSM4_GCM,
    /// <summary>PBEWithHMACSM3AndSM4_CBC — SM4-CBC with Encrypt-then-HMAC-SM3.</summary>
    PBEWithHMACSM3AndSM4_CBC
}
