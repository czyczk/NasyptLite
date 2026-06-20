using NasyptLite;

namespace NasyptLite.SourceGen.Tests;

// ── Test subject classes (exercise the source generator) ─────────────

[NasyptDecrypt]
public partial class BasicConfig
{
    public string Url { get; set; } = "";

    [Encrypted]
    public string Password { get; set; } = "";
}

[NasyptDecrypt]
public partial class NullableConfig
{
    [Encrypted]
    public string? ApiKey { get; set; }
}

[NasyptDecrypt]
public partial class MultiAlgoConfig
{
    [Encrypted]
    public string DefaultField { get; set; } = "";

    [Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_GCM")]
    public string Sm4GcmField { get; set; } = "";

    [Encrypted(Algorithm = "PBEWithHMACSM3AndSM4_CBC")]
    public string Sm4CbcField { get; set; } = "";

    public string NotEncrypted { get; set; } = "";
}

[NasyptDecrypt]
internal partial class InternalConfig
{
    [Encrypted]
    public string Secret { get; set; } = "";
}

// ── Tests ────────────────────────────────────────────────────────────

[TestClass]
public sealed class SourceGenIntegrationTests
{
    private const string Password = "test-password-1234";

    [TestMethod]
    public void BasicConfig_DecryptEncFields_DecryptsEncryptedField()
    {
        var encrypted = Nasypt.Encrypt(Password, "my-secret");
        var config = new BasicConfig
        {
            Url = "https://example.com",
            Password = $"ENC({encrypted})"
        };

        config.DecryptEncFields(Password);

        Assert.AreEqual("my-secret", config.Password);
        Assert.AreEqual("https://example.com", config.Url);
    }

    [TestMethod]
    public void BasicConfig_ImplementsIDisposable()
    {
        Assert.IsInstanceOfType<System.IDisposable>(new BasicConfig());
    }

    [TestMethod]
    public void NullableConfig_NullField_IsSkipped()
    {
        var config = new NullableConfig { ApiKey = null };
        config.DecryptEncFields(Password);
        Assert.IsNull(config.ApiKey);
    }

    [TestMethod]
    public void NullableConfig_NonNullField_IsDecrypted()
    {
        var encrypted = Nasypt.Encrypt(Password, "key-12345");
        var config = new NullableConfig { ApiKey = $"ENC({encrypted})" };

        config.DecryptEncFields(Password);

        Assert.AreEqual("key-12345", config.ApiKey);
    }

    [TestMethod]
    public void NullableConfig_ClearSensitiveFields_NullifiesValue()
    {
        var config = new NullableConfig { ApiKey = "sensitive" };
        config.ClearSensitiveFields();
        Assert.IsNull(config.ApiKey);
    }

    [TestMethod]
    public void MultiAlgoConfig_EachFieldUsesCorrectAlgorithm()
    {
        var aesEnc = Nasypt.Encrypt(Password, "aes-secret");
        var gcmEnc = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, "gcm-secret");
        var cbcEnc = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, "cbc-secret");

        var config = new MultiAlgoConfig
        {
            DefaultField = $"ENC({aesEnc})",
            Sm4GcmField = $"ENC({gcmEnc})",
            Sm4CbcField = $"ENC({cbcEnc})",
            NotEncrypted = "plain"
        };

        config.DecryptEncFields(Password);

        Assert.AreEqual("aes-secret", config.DefaultField);
        Assert.AreEqual("gcm-secret", config.Sm4GcmField);
        Assert.AreEqual("cbc-secret", config.Sm4CbcField);
        Assert.AreEqual("plain", config.NotEncrypted);
    }

    [TestMethod]
    public void InternalConfig_WorksWithInternalAccessibility()
    {
        var encrypted = Nasypt.Encrypt(Password, "internal-test");
        var config = new InternalConfig { Secret = $"ENC({encrypted})" };

        config.DecryptEncFields(Password);

        Assert.AreEqual("internal-test", config.Secret);
    }

    [TestMethod]
    public void Dispose_ClearsSensitiveFields()
    {
        var config = new BasicConfig();
        config.Password = "sensitive";
        config.Dispose();
        Assert.AreEqual("", config.Password);
    }

    [TestMethod]
    public void NonEncValue_IsLeftUnchanged()
    {
        var config = new BasicConfig { Password = "not-enc-wrapped" };
        config.DecryptEncFields(Password);
        Assert.AreEqual("not-enc-wrapped", config.Password);
    }

    [TestMethod]
    public void ClearSensitiveFields_ClearsStringField()
    {
        var config = new BasicConfig { Password = "sensitive" };
        config.ClearSensitiveFields();
        Assert.AreEqual("", config.Password);
    }
}
