using NasyptLite;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Generators;
using System.Text;
using System.Security.Cryptography;

namespace NasyptLite.Tests;

[TestClass]
public sealed class Sm4CompatTests
{
    // RFC 8998 Appendix A.1 SM4-GCM test vector
    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static string BytesToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes);
    }

    [TestMethod]
    public void Rfc8998_Sm4Gcm_Encrypt_MatchesTestVector()
    {
        var key = HexToBytes("0123456789ABCDEFFEDCBA9876543210");
        var nonce = HexToBytes("00001234567800000000ABCD");
        var plaintext = HexToBytes(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB" +
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
            "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF" +
            "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
        var aad = HexToBytes("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        var expectedCt = HexToBytes(
            "17F399F08C67D5EE19D0DC9969C4BB7D" +
            "5FD46FD3756489069157B282BB200735" +
            "D82710CA5C22F0CCFA7CBF93D496AC15" +
            "A56834CBCF98C397B4024A2691233B8D");
        var expectedTag = HexToBytes("83DE3541E4C2B58177E065A9BF7B62EC");

        var cipher = new GcmBlockCipher(new SM4Engine());
        var parameters = new AeadParameters(new KeyParameter(key), 128, nonce, aad);
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);

        var ct = new byte[expectedCt.Length];
        var tag = new byte[16];
        Array.Copy(output, 0, ct, 0, ct.Length);
        Array.Copy(output, ct.Length, tag, 0, 16);

        CollectionAssert.AreEqual(expectedCt, ct, $"CT mismatch. Got: {BytesToHex(ct)}");
        CollectionAssert.AreEqual(expectedTag, tag, $"Tag mismatch. Got: {BytesToHex(tag)}");

        var decInput = new byte[ct.Length + 16];
        Array.Copy(ct, 0, decInput, 0, ct.Length);
        Array.Copy(tag, 0, decInput, ct.Length, 16);

        cipher.Init(false, parameters);
        var decOut = new byte[cipher.GetOutputSize(decInput.Length)];
        var decLen = cipher.ProcessBytes(decInput, 0, decInput.Length, decOut, 0);
        decLen += cipher.DoFinal(decOut, decLen);
        var decResult = new byte[decLen];
        Array.Copy(decOut, 0, decResult, 0, decLen);
        CollectionAssert.AreEqual(plaintext, decResult);
    }

    [TestMethod]
    public void Sm4Gcm_RoundTrip_WithBouncyCastle_Directly()
    {
        var key = new byte[16];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World! This is a test.");
        var aad = Encoding.UTF8.GetBytes("some aad data");

        var cipher = new GcmBlockCipher(new SM4Engine());
        var parameters = new AeadParameters(new KeyParameter(key), 128, nonce, aad);
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);

        var ct = new byte[len - 16];
        var tag = new byte[16];
        Array.Copy(output, 0, ct, 0, ct.Length);
        Array.Copy(output, ct.Length, tag, 0, 16);

        var decInput = new byte[ct.Length + 16];
        Array.Copy(ct, 0, decInput, 0, ct.Length);
        Array.Copy(tag, 0, decInput, ct.Length, 16);

        cipher.Init(false, parameters);
        var decOut = new byte[cipher.GetOutputSize(decInput.Length)];
        var decLen = cipher.ProcessBytes(decInput, 0, decInput.Length, decOut, 0);
        decLen += cipher.DoFinal(decOut, decLen);
        var decResult = new byte[decLen];
        Array.Copy(decOut, 0, decResult, 0, decLen);

        CollectionAssert.AreEqual(plaintext, decResult);
    }

    [TestMethod]
    public void Pbkdf2_Sm3_Outputs48Bytes()
    {
        var password = "test-password"u8.ToArray();
        var salt = "12345678abcdefgh"u8.ToArray();
        var generator = new Pkcs5S2ParametersGenerator(new SM3Digest());
        generator.Init(password, salt, 10000);
        var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(48 * 8);
        var derived = keyParam.GetKey();
        Assert.HasCount(48, derived);
    }

    [TestMethod]
    public void CrossCompatibility_RustSm4GcmToDotNet()
    {
        var rustGcmCipher = "BTIg1Xc6631o2RSTAobTITI9pWdEJNZL0NidD2l8yuIo/bJgVSXvYZuIhpxpynN/8NxevqXQZycMf4bR0lEXtCnqlzQSfRk4MBfixxpDWOaxeGG/qwe7KmmQ3Q==";
        var plaintext = Nasypt.DecryptWith(Algorithm.PBEWithHMACSM3AndSM4_GCM, "shared-secret", rustGcmCipher);
        Assert.AreEqual("Sm4GcmCrossTest", plaintext);
    }

}
