namespace NasyptLite;

/// <summary>Marks a <c>string</c> or <c>string?</c> property for automatic ENC(…) decryption.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = false)]
public class EncryptedAttribute : Attribute
{
    /// <summary>Optional algorithm name override (e.g. "PBEWithHMACSM3AndSM4_GCM").</summary>
    public string? Algorithm { get; set; }
}
