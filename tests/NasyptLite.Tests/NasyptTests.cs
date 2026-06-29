using NasyptLite;

namespace NasyptLite.Tests;

[TestClass]
public sealed class NasyptTests
{
    private const string Password = "test-password-1234";
    private const string Plaintext = "Hello, World! This is a test.";

    // ── convenience overloads (default AES) ─────────────────────────

    [TestMethod]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginal()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var decrypted = Nasypt.Decrypt(Password, encrypted);
        Assert.AreEqual(Plaintext, decrypted);
    }

    // ── AES-256-CBC explicit ────────────────────────────────────────

    [TestMethod]
    public void Aes_EncryptWith_DecryptWith_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, Plaintext);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, encrypted);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void Aes_CustomIterations_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, Plaintext, 5000);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, encrypted, 5000);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void DecryptWith_NegativeIterations_ThrowsInvalidIterations()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, encrypted, -1));
        Assert.AreEqual(NasyptError.InvalidIterations, ex.ErrorCode);
    }

    [TestMethod]
    public void Aes_DifferentCalls_ProduceDifferentCiphertexts()
    {
        var a = Nasypt.Encrypt(Password, Plaintext);
        var b = Nasypt.Encrypt(Password, Plaintext);
        Assert.AreNotEqual(a, b);
    }

    // ── SM4-GCM ─────────────────────────────────────────────────────

    [TestMethod]
    public void Sm4Gcm_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void Sm4Gcm_DifferentEncryptionsDiffer()
    {
        var a = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var b = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        Assert.AreNotEqual(a, b);
    }

    [TestMethod]
    public void Sm4Gcm_WrongPassword_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, "wrong-password", encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Gcm_TamperedCiphertext_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var bytes = Convert.FromBase64String(encrypted);
        var tamperPos = Nasypt.SaltSize + 12 + 2;
        if (tamperPos < bytes.Length - 16 - 32)
            bytes[tamperPos] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, tampered));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Gcm_EmptyPlaintext_Works()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, "");
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted);
        Assert.AreEqual("", decrypted);
    }

    [TestMethod]
    public void Sm4Gcm_LongPlaintext_Works()
    {
        var longText = new string('x', 10000);
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, longText);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted);
        Assert.AreEqual(longText, decrypted);
    }

    [TestMethod]
    public void Sm4Gcm_CrossAlgorithm_RejectedByAes()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    // ── SM4-CBC ─────────────────────────────────────────────────────

    [TestMethod]
    public void Sm4Cbc_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void Sm4Cbc_DifferentEncryptionsDiffer()
    {
        var a = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var b = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        Assert.AreNotEqual(a, b);
    }

    [TestMethod]
    public void Sm4Cbc_WrongPassword_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, "wrong-password", encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Cbc_TamperedCiphertext_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var bytes = Convert.FromBase64String(encrypted);
        var tamperPos = Nasypt.SaltSize + 16 + 2;
        if (tamperPos < bytes.Length - 32)
            bytes[tamperPos] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, tampered));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Cbc_EmptyPlaintext_Works()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, "");
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted);
        Assert.AreEqual("", decrypted);
    }

    [TestMethod]
    public void Sm4Cbc_LongPlaintext_Works()
    {
        var longText = new string('x', 10000);
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, longText);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted);
        Assert.AreEqual(longText, decrypted);
    }

    [TestMethod]
    public void Sm4Cbc_CrossAlgorithm_RejectedByAes()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Gcm_RejectsCbcCiphertext()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Sm4Cbc_RejectsGcmCiphertext()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    // ── ENC(…) wrapping ─────────────────────────────────────────────

    [TestMethod]
    public void EncWith_DecryptEnc_RoundTrip_ReturnsOriginal()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var wrapped = $"ENC({encrypted})";
        Assert.IsTrue(Nasypt.IsEncValue(wrapped));
        var decrypted = Nasypt.DecryptEnc(wrapped, Password);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void EncWith_DecryptEncWith_RoundTrip_ReturnsOriginal()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var wrapped = $"ENC({encrypted})";
        var decrypted = Nasypt.DecryptEncWith(Algorithm.PBEWithHMACSHA512AndAES_256, wrapped, Password);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void DecryptEnc_NotEncValue_ThrowsNotEncValue()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptEnc("not-an-enc-value", Password));
        Assert.AreEqual(NasyptError.NotEncValue, ex.ErrorCode);
    }

    // ── IsEncValue / TryUnwrapEnc ────────────────────────────────────

    [TestMethod]
    public void IsEncValue_ValidEnc_ReturnsTrue()
    {
        Assert.IsTrue(Nasypt.IsEncValue("ENC(abcd)"));
    }

    [TestMethod]
    public void IsEncValue_WithWhitespace_ReturnsTrue()
    {
        Assert.IsTrue(Nasypt.IsEncValue("  ENC(abcd)  "));
    }

    [TestMethod]
    public void IsEncValue_NoEncPrefix_ReturnsFalse()
    {
        Assert.IsFalse(Nasypt.IsEncValue("NOT_ENC(abcd)"));
    }

    [TestMethod]
    public void IsEncValue_MissingParen_ReturnsFalse()
    {
        Assert.IsFalse(Nasypt.IsEncValue("ENC(abcd"));
    }

    [TestMethod]
    public void IsEncValue_PlainText_ReturnsFalse()
    {
        Assert.IsFalse(Nasypt.IsEncValue("just some text"));
    }

    [TestMethod]
    public void IsEncValue_Empty_ReturnsFalse()
    {
        Assert.IsFalse(Nasypt.IsEncValue(""));
    }

    [TestMethod]
    public void IsEncValue_TooShort_ReturnsFalse()
    {
        Assert.IsFalse(Nasypt.IsEncValue("ENC()"));
    }

    [TestMethod]
    public void TryUnwrapEnc_Valid_ReturnsTrueAndContent()
    {
        Assert.IsTrue(Nasypt.TryUnwrapEnc("ENC(base64stuff)", out var inner));
        Assert.AreEqual("base64stuff", inner);
    }

    [TestMethod]
    public void TryUnwrapEnc_WithWhitespace_ReturnsTrueAndContent()
    {
        Assert.IsTrue(Nasypt.TryUnwrapEnc("  ENC(base64stuff)  ", out var inner));
        Assert.AreEqual("base64stuff", inner);
    }

    [TestMethod]
    public void TryUnwrapEnc_NotEnc_ReturnsFalseAndNullInner()
    {
        Assert.IsFalse(Nasypt.TryUnwrapEnc("plain text", out var inner));
        Assert.IsNull(inner);
    }

    // ── error conditions ─────────────────────────────────────────────

    [TestMethod]
    public void Decrypt_WrongPassword_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt("wrong-password", encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Decrypt_BadBase64_ThrowsFailedToDecodeBase64()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt(Password, "!!!not-base64!!!"));
        Assert.AreEqual(NasyptError.FailedToDecodeBase64, ex.ErrorCode);
    }

    [TestMethod]
    public void Decrypt_TooShortInput_ThrowsCiphertextTooShort()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt(Password, "YWJj"));
        Assert.AreEqual(NasyptError.CiphertextTooShort, ex.ErrorCode);
    }

    [TestMethod]
    public void Decrypt_TamperedCiphertext_ThrowsDecryptionFailed()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var bytes = Convert.FromBase64String(encrypted);
        bytes[^1] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt(Password, tampered));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void WrongPassword_ErrorMessage_IsGeneric()
    {
        var encrypted = Nasypt.Encrypt(Password, Plaintext);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt("wrong-pass", encrypted));
        StringAssert.Contains(ex.Message, "Decryption failed");
    }

    // ── iteration validation ────────────────────────────────────────

    [TestMethod]
    public void EncryptWith_NegativeIterations_ThrowsInvalidIterations()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, Plaintext, -1));
        Assert.AreEqual(NasyptError.InvalidIterations, ex.ErrorCode);
    }

    [TestMethod]
    public void EncryptWith_ZeroIterations_ThrowsInvalidIterations()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, Plaintext, 0));
        Assert.AreEqual(NasyptError.InvalidIterations, ex.ErrorCode);
    }

    // ── edge cases ───────────────────────────────────────────────────

    [TestMethod]
    public void Encrypt_EmptyPlaintext_Works()
    {
        var encrypted = Nasypt.Encrypt(Password, "");
        var decrypted = Nasypt.Decrypt(Password, encrypted);
        Assert.AreEqual("", decrypted);
    }

    [TestMethod]
    public void Encrypt_LongPlaintext_Works()
    {
        var longText = new string('x', 10000);
        var encrypted = Nasypt.Encrypt(Password, longText);
        var decrypted = Nasypt.Decrypt(Password, encrypted);
        Assert.AreEqual(longText, decrypted);
    }

    [TestMethod]
    public void Encrypt_UnicodePlaintext_Works()
    {
        var unicode = "Hello \u4e16\u754c \U0001f30d caf\u00e9 na\u00efve";
        var encrypted = Nasypt.Encrypt(Password, unicode);
        var decrypted = Nasypt.Decrypt(Password, encrypted);
        Assert.AreEqual(unicode, decrypted);
    }

    [TestMethod]
    public void Encrypt_UnicodePassword_Works()
    {
        var unicodePassword = "\u30d1\u30b9\u30ef\u30fc\u30c9\U0001f511\u6d4b\u8bd5";
        var encrypted = Nasypt.Encrypt(unicodePassword, Plaintext);
        var decrypted = Nasypt.Decrypt(unicodePassword, encrypted);
        Assert.AreEqual(Plaintext, decrypted);
    }

    // ── memory hygiene ───────────────────────────────────────────────

    [TestMethod]
    public void ClearString_ReturnsEmpty()
    {
        var result = Nasypt.ClearString("sensitive");
        Assert.AreEqual("", result);
    }

    [TestMethod]
    public void ClearString_Null_ReturnsEmpty()
    {
        var result = Nasypt.ClearString(null);
        Assert.AreEqual("", result);
    }

    [TestMethod]
    public void ClearOptionString_ReturnsNull()
    {
        var result = Nasypt.ClearOptionString("sensitive");
        Assert.IsNull(result);
    }

    [TestMethod]
    public void ClearOptionString_Null_ReturnsNull()
    {
        var result = Nasypt.ClearOptionString(null);
        Assert.IsNull(result);
    }

    // ── cross-compatibility with Rust rasypt-lite ─────────────────────

    [TestMethod]
    public void CrossCompatibility_RustAes_DotNetDecrypt()
    {
        var rustEncrypted = "6gD8kVrpCIm0zf2NfQvhbtPD78o4qkIrscU6XERfG9FQ2x5LE86MZY/uOvViiO8W";
        var decrypted = Nasypt.Decrypt("shared-secret", rustEncrypted);
        Assert.AreEqual("CrossCompatTest", decrypted);
    }

    // ── error-code assertions ────────────────────────────────────────

    [TestMethod]
    public void DecryptEnc_PlainText_ErrorCodeIsNotEncValue()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptEnc("plaintext", Password));
        Assert.AreEqual(NasyptError.NotEncValue, ex.ErrorCode);
    }

    [TestMethod]
    public void Decrypt_BadBase64_ErrorCodeIsFailedToDecodeBase64()
    {
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.Decrypt(Password, "=="));
        Assert.AreEqual(NasyptError.FailedToDecodeBase64, ex.ErrorCode);
    }

    // ── cross-algorithm rejection ────────────────────────────────────

    [TestMethod]
    public void Aes_RejectedBySm4Gcm()
    {
        var longText = new string('x', 100);
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, longText);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    [TestMethod]
    public void Aes_RejectedBySm4Cbc()
    {
        var longText = new string('x', 100);
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, Password, longText);
        var ex = Assert.Throws<NasyptException>(() =>
            Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted));
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
    }

    // ── SM4 custom iterations ────────────────────────────────────────

    [TestMethod]
    public void Sm4Gcm_CustomIterations_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext, 5000);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, encrypted, 5000);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void Sm4Cbc_CustomIterations_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext, 5000);
        var decrypted = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, encrypted, 5000);
        Assert.AreEqual(Plaintext, decrypted);
    }

    // ── DecryptEncWith SM algorithms ─────────────────────────────────

    [TestMethod]
    public void DecryptEncWith_Sm4Gcm_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, Password, Plaintext);
        var wrapped = $"ENC({encrypted})";
        var decrypted = Nasypt.DecryptEncWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, wrapped, Password);
        Assert.AreEqual(Plaintext, decrypted);
    }

    [TestMethod]
    public void DecryptEncWith_Sm4Cbc_RoundTrip()
    {
        var encrypted = Nasypt.EncryptWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, Password, Plaintext);
        var wrapped = $"ENC({encrypted})";
        var decrypted = Nasypt.DecryptEncWith(Algorithm.PBEWithHMACSM3AndSM4_CBC, wrapped, Password);
        Assert.AreEqual(Plaintext, decrypted);
    }

    // ── NasyptException ──────────────────────────────────────────────

    [TestMethod]
    public void NasyptException_WithInnerException_PreservesErrorCode()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new NasyptException(NasyptError.DecryptionFailed, inner);
        Assert.AreEqual(NasyptError.DecryptionFailed, ex.ErrorCode);
        Assert.AreSame(inner, ex.InnerException);
    }

    // ── SupportedAlgorithms ──────────────────────────────────────────

    [TestMethod]
    public void SupportedAlgorithms_ContainsAllThree()
    {
        var algos = Nasypt.SupportedAlgorithms;
        Assert.HasCount(3, algos);
        CollectionAssert.Contains((System.Collections.ICollection)algos, Algorithm.PBEWithHMACSHA512AndAES_256);
        CollectionAssert.Contains((System.Collections.ICollection)algos, Algorithm.PBEWithHMACSM3AndSM4_GCM);
        CollectionAssert.Contains((System.Collections.ICollection)algos, Algorithm.PBEWithHMACSM3AndSM4_CBC);
    }
}
