using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace NasyptLite;

/// <summary>
/// Jasypt-compatible password-based encryption using PBKDF2 + AES/SM4.
/// Wire format is cross-compatible with the Rust rasypt-lite library.
/// </summary>
public static class Nasypt
{
    /// <summary>Default PBKDF2 iteration count for AES-256-CBC (1,000).</summary>
    public const int DefaultIterations = 1000;
    /// <summary>Default PBKDF2 iteration count for SM4 algorithms (10,000).</summary>
    public const int DefaultSmIterations = 10000;
    /// <summary>Salt size in bytes.</summary>
    public const int SaltSize = 16;
    /// <summary>AES / SM4-CBC IV size in bytes.</summary>
    public const int IvSize = 16;
    /// <summary>AES-256 key size in bytes.</summary>
    public const int KeySize = 32;
    private const int DerivedKeyLength = KeySize;

    private const int Sm4KeySize = 16;
    private const int Sm4BlockSize = 16;
    private const int Sm4GcmNonceSize = 12;
    private const int Sm4GcmTagSize = 16;
    private const int HmacSm3Output = 32;
    private const int Sm4CbcDkLen = Sm4KeySize + HmacSm3Output; // 48
    private const int Sm4GcmDkLen = Sm4KeySize + HmacSm3Output; // 48

    private static readonly string[] KnownAlgorithms =
        Enum.GetNames<Algorithm>();

    /// <summary>Returns all supported algorithm variants.</summary>
    public static IReadOnlyList<Algorithm> SupportedAlgorithms { get; } =
        Enum.GetValues<Algorithm>();

    // ── convenience overloads ────────────────────────────────────────

    /// <summary>Encrypts <paramref name="plaintext"/> with the default algorithm (AES-256-CBC).</summary>
    public static string Encrypt(string password, string plaintext)
    {
        return EncryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, password, plaintext);
    }

    /// <summary>Decrypts a Base64-encoded ciphertext with the default algorithm.</summary>
    public static string Decrypt(string password, string encoded)
    {
        return DecryptWith(Algorithm.PBEWithHMACSHA512AndAES_256, password, encoded);
    }

    // ── algorithm-aware encrypt / decrypt ────────────────────────────

    /// <summary>Encrypts with the specified <paramref name="algorithm"/>.</summary>
    public static string EncryptWith(Algorithm algorithm, string password, string plaintext, int? iterations = null)
    {
        ValidateAlgorithm(algorithm);
        var iter = iterations ?? DefaultIterationsFor(algorithm);
        ValidateIterations(iter);

        return algorithm switch
        {
            Algorithm.PBEWithHMACSHA512AndAES_256 => EncryptAes(password, plaintext, iter),
            Algorithm.PBEWithHMACSM3AndSM4_GCM => EncryptSm4Gcm(password, plaintext, iter),
            Algorithm.PBEWithHMACSM3AndSM4_CBC => EncryptSm4Cbc(password, plaintext, iter),
            _ => throw new NasyptException(NasyptError.UnknownAlgorithm)
        };
    }

    /// <summary>Decrypts a Base64-encoded ciphertext with the specified <paramref name="algorithm"/>.</summary>
    public static string DecryptWith(Algorithm algorithm, string password, string encoded, int? iterations = null)
    {
        ValidateAlgorithm(algorithm);
        var iter = iterations ?? DefaultIterationsFor(algorithm);
        ValidateIterations(iter);

        return algorithm switch
        {
            Algorithm.PBEWithHMACSHA512AndAES_256 => DecryptAes(password, encoded, iter),
            Algorithm.PBEWithHMACSM3AndSM4_GCM => DecryptSm4Gcm(password, encoded, iter),
            Algorithm.PBEWithHMACSM3AndSM4_CBC => DecryptSm4Cbc(password, encoded, iter),
            _ => throw new NasyptException(NasyptError.UnknownAlgorithm)
        };
    }

    // ── ENC(…) helpers ───────────────────────────────────────────────

    /// <summary>Decrypts an <c>ENC(base64)</c>-wrapped value with the default algorithm.</summary>
    public static string DecryptEnc(string value, string password)
    {
        return DecryptEncWith(Algorithm.PBEWithHMACSHA512AndAES_256, value, password);
    }

    /// <summary>Decrypts an <c>ENC(base64)</c>-wrapped value with the specified <paramref name="algorithm"/>.</summary>
    public static string DecryptEncWith(Algorithm algorithm, string value, string password)
    {
        if (!TryUnwrapEnc(value, out var inner))
            throw new NasyptException(NasyptError.NotEncValue);

        return DecryptWith(algorithm, password, inner!);
    }

    /// <summary>Returns <c>true</c> if <paramref name="value"/> is wrapped in <c>ENC(…)</c>.</summary>
    public static bool IsEncValue(string value)
    {
        return TryUnwrapEnc(value, out _);
    }

    /// <summary>Extracts the inner Base64 content from an <c>ENC(…)</c> wrapper, or returns <c>false</c>.</summary>
    public static bool TryUnwrapEnc(string value, out string? inner)
    {
        var t = value.AsSpan().Trim();
        if (t.Length >= 6 && t.StartsWith("ENC(", StringComparison.Ordinal) && t.EndsWith(")"))
        {
            inner = t[4..^1].ToString();
            return true;
        }

        inner = null;
        return false;
    }

    // ── memory hygiene ───────────────────────────────────────────────

    /// <summary>
    /// Returns <see cref="string.Empty"/> so the caller can replace a sensitive
    /// <c>string</c> field or variable. Strings are immutable in .NET — the
    /// caller <b>must</b> assign the result back: <c>myProp = Nasypt.ClearString(myProp);</c>
    /// </summary>
    public static string ClearString(string? s)
    {
        return string.Empty;
    }

    /// <summary>
    /// Returns <c>null</c> so the caller can replace a nullable sensitive
    /// <c>string?</c> field or variable. Strings are immutable in .NET — the
    /// caller <b>must</b> assign the result back.
    /// </summary>
    public static string? ClearOptionString(string? s)
    {
        return null;
    }

    // ── validation ───────────────────────────────────────────────────

    private static void ValidateAlgorithm(Algorithm algorithm)
    {
        var name = algorithm.ToString();
        if (Array.IndexOf(KnownAlgorithms, name) < 0)
            throw new NasyptException(NasyptError.UnknownAlgorithm);
    }

    private static void ValidateIterations(int iterations)
    {
        if (iterations <= 0)
            throw new NasyptException(NasyptError.InvalidIterations);
    }

    private static int DefaultIterationsFor(Algorithm algorithm)
    {
        return algorithm switch
        {
            Algorithm.PBEWithHMACSHA512AndAES_256 => DefaultIterations,
            Algorithm.PBEWithHMACSM3AndSM4_GCM => DefaultSmIterations,
            Algorithm.PBEWithHMACSM3AndSM4_CBC => DefaultSmIterations,
            _ => DefaultIterations
        };
    }

    // ── AES-256-CBC (Jasypt-compatible) ──────────────────────────────

    private static string EncryptAes(string password, string plaintext, int iterations)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var iv = new byte[IvSize];
        RandomNumberGenerator.Fill(iv);

        var key = DeriveAesKey(password, salt, iterations);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        byte[] ciphertext;
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor())
            {
                ciphertext = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
            }
        }

        var result = new byte[SaltSize + IvSize + ciphertext.Length];
        Array.Copy(salt, 0, result, 0, SaltSize);
        Array.Copy(iv, 0, result, SaltSize, IvSize);
        Array.Copy(ciphertext, 0, result, SaltSize + IvSize, ciphertext.Length);

        CryptographicOperations.ZeroMemory(key);

        return Convert.ToBase64String(result);
    }

    private static string DecryptAes(string password, string encoded, int iterations)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(encoded);
        }
        catch (FormatException ex)
        {
            throw new NasyptException(NasyptError.FailedToDecodeBase64, ex);
        }

        if (raw.Length < SaltSize + IvSize + 1)
            throw new NasyptException(NasyptError.CiphertextTooShort);

        var salt = new byte[SaltSize];
        var iv = new byte[IvSize];
        var ciphertext = new byte[raw.Length - SaltSize - IvSize];
        Array.Copy(raw, 0, salt, 0, SaltSize);
        Array.Copy(raw, SaltSize, iv, 0, IvSize);
        Array.Copy(raw, SaltSize + IvSize, ciphertext, 0, ciphertext.Length);

        var key = DeriveAesKey(password, salt, iterations);

        byte[] plaintext;
        try
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
        }
        catch (CryptographicException ex)
        {
            throw new NasyptException(NasyptError.DecryptionFailed, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] DeriveAesKey(string password, byte[] salt, int iterations)
    {
        var normalizedPassword = password.Normalize(NormalizationForm.FormC);
        var passwordBytes = Encoding.UTF8.GetBytes(normalizedPassword);
        var derived = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA512, KeySize);
        CryptographicOperations.ZeroMemory(passwordBytes);
        return derived;
    }

    // ── SM4 key derivation (PBKDF2-HMAC-SM3) ─────────────────────────

    private static byte[] DeriveSmKey(string password, byte[] salt, int iterations, int keyLength)
    {
        var normalized = password.Normalize(NormalizationForm.FormC);
        var passwordBytes = Encoding.UTF8.GetBytes(normalized);
        var generator = new Pkcs5S2ParametersGenerator(new SM3Digest());
        generator.Init(passwordBytes, salt, iterations);
        var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(keyLength * 8);
        CryptographicOperations.ZeroMemory(passwordBytes);
        return keyParam.GetKey();
    }

    // ── SM4-GCM ──────────────────────────────────────────────────────

    private static string EncryptSm4Gcm(string password, string plaintext, int iterations)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var nonce = new byte[Sm4GcmNonceSize];
        RandomNumberGenerator.Fill(nonce);

        var dk = DeriveSmKey(password, salt, iterations, Sm4GcmDkLen);
        var encKey = new byte[Sm4KeySize];
        var commitKey = new byte[HmacSm3Output];
        Array.Copy(dk, 0, encKey, 0, Sm4KeySize);
        Array.Copy(dk, Sm4KeySize, commitKey, 0, HmacSm3Output);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var (ciphertext, tag) = Sm4GcmEncrypt(encKey, nonce, salt, plaintextBytes);

        var commitment = ComputeHmacSm3(commitKey, salt, nonce, ciphertext, tag);

        var output = new byte[SaltSize + Sm4GcmNonceSize + ciphertext.Length + Sm4GcmTagSize + HmacSm3Output];
        var pos = 0;
        Array.Copy(salt, 0, output, pos, SaltSize); pos += SaltSize;
        Array.Copy(nonce, 0, output, pos, Sm4GcmNonceSize); pos += Sm4GcmNonceSize;
        Array.Copy(ciphertext, 0, output, pos, ciphertext.Length); pos += ciphertext.Length;
        Array.Copy(tag, 0, output, pos, Sm4GcmTagSize); pos += Sm4GcmTagSize;
        Array.Copy(commitment, 0, output, pos, HmacSm3Output);

        CryptographicOperations.ZeroMemory(dk);
        CryptographicOperations.ZeroMemory(encKey);
        CryptographicOperations.ZeroMemory(commitKey);

        return Convert.ToBase64String(output);
    }

    private static string DecryptSm4Gcm(string password, string encoded, int iterations)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(encoded);
        }
        catch (FormatException ex)
        {
            throw new NasyptException(NasyptError.FailedToDecodeBase64, ex);
        }

        var minLen = SaltSize + Sm4GcmNonceSize + Sm4GcmTagSize + HmacSm3Output;
        if (raw.Length < minLen)
            throw new NasyptException(NasyptError.CiphertextTooShort);

        var salt = new byte[SaltSize];
        var nonce = new byte[Sm4GcmNonceSize];
        Array.Copy(raw, 0, salt, 0, SaltSize);
        Array.Copy(raw, SaltSize, nonce, 0, Sm4GcmNonceSize);

        var commitmentStart = raw.Length - HmacSm3Output;
        var tagStart = commitmentStart - Sm4GcmTagSize;
        var ciphertextLen = tagStart - (SaltSize + Sm4GcmNonceSize);

        var ciphertext = new byte[ciphertextLen];
        var tag = new byte[Sm4GcmTagSize];
        var receivedCommitment = new byte[HmacSm3Output];
        Array.Copy(raw, SaltSize + Sm4GcmNonceSize, ciphertext, 0, ciphertextLen);
        Array.Copy(raw, tagStart, tag, 0, Sm4GcmTagSize);
        Array.Copy(raw, commitmentStart, receivedCommitment, 0, HmacSm3Output);

        var dk = DeriveSmKey(password, salt, iterations, Sm4GcmDkLen);
        var encKey = new byte[Sm4KeySize];
        var commitKey = new byte[HmacSm3Output];
        Array.Copy(dk, 0, encKey, 0, Sm4KeySize);
        Array.Copy(dk, Sm4KeySize, commitKey, 0, HmacSm3Output);

        try
        {
            if (!ConstantTimeEquals(ComputeHmacSm3(commitKey, salt, nonce, ciphertext, tag), receivedCommitment))
                throw new NasyptException(NasyptError.DecryptionFailed);

            var plaintext = Sm4GcmDecrypt(encKey, nonce, salt, ciphertext, tag);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (InvalidCipherTextException ex)
        {
            throw new NasyptException(NasyptError.DecryptionFailed, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dk);
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(commitKey);
        }
    }

    private static (byte[] Ciphertext, byte[] Tag) Sm4GcmEncrypt(
        byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        var cipher = new GcmBlockCipher(new SM4Engine());
        var parameters = new AeadParameters(new KeyParameter(key), Sm4GcmTagSize * 8, nonce, aad);
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);
        var resultTag = new byte[Sm4GcmTagSize];
        var ct = new byte[len - Sm4GcmTagSize];
        Array.Copy(output, 0, ct, 0, ct.Length);
        Array.Copy(output, ct.Length, resultTag, 0, Sm4GcmTagSize);
        return (ct, resultTag);
    }

    private static byte[] Sm4GcmDecrypt(
        byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        var cipher = new GcmBlockCipher(new SM4Engine());
        var parameters = new AeadParameters(new KeyParameter(key), Sm4GcmTagSize * 8, nonce, aad);
        cipher.Init(false, parameters);

        var input = new byte[ciphertext.Length + Sm4GcmTagSize];
        Array.Copy(ciphertext, 0, input, 0, ciphertext.Length);
        Array.Copy(tag, 0, input, ciphertext.Length, Sm4GcmTagSize);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        var result = new byte[len];
        Array.Copy(output, 0, result, 0, len);
        return result;
    }

    // ── SM4-CBC ──────────────────────────────────────────────────────

    private static string EncryptSm4Cbc(string password, string plaintext, int iterations)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var iv = new byte[Sm4BlockSize];
        RandomNumberGenerator.Fill(iv);

        var dk = DeriveSmKey(password, salt, iterations, Sm4CbcDkLen);
        var encKey = new byte[Sm4KeySize];
        var macKey = new byte[HmacSm3Output];
        Array.Copy(dk, 0, encKey, 0, Sm4KeySize);
        Array.Copy(dk, Sm4KeySize, macKey, 0, HmacSm3Output);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var ciphertext = Sm4CbcProcess(true, encKey, iv, plaintextBytes);
        var mac = ComputeHmacSm3(macKey, iv, ciphertext);

        var output = new byte[SaltSize + Sm4BlockSize + ciphertext.Length + HmacSm3Output];
        var pos = 0;
        Array.Copy(salt, 0, output, pos, SaltSize); pos += SaltSize;
        Array.Copy(iv, 0, output, pos, Sm4BlockSize); pos += Sm4BlockSize;
        Array.Copy(ciphertext, 0, output, pos, ciphertext.Length); pos += ciphertext.Length;
        Array.Copy(mac, 0, output, pos, HmacSm3Output);

        CryptographicOperations.ZeroMemory(dk);
        CryptographicOperations.ZeroMemory(encKey);
        CryptographicOperations.ZeroMemory(macKey);

        return Convert.ToBase64String(output);
    }

    private static string DecryptSm4Cbc(string password, string encoded, int iterations)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(encoded);
        }
        catch (FormatException ex)
        {
            throw new NasyptException(NasyptError.FailedToDecodeBase64, ex);
        }

        var minLen = SaltSize + Sm4BlockSize + 1 + HmacSm3Output;
        if (raw.Length < minLen)
            throw new NasyptException(NasyptError.CiphertextTooShort);

        var salt = new byte[SaltSize];
        var iv = new byte[Sm4BlockSize];
        Array.Copy(raw, 0, salt, 0, SaltSize);
        Array.Copy(raw, SaltSize, iv, 0, Sm4BlockSize);

        var macStart = raw.Length - HmacSm3Output;
        var ciphertextLen = macStart - (SaltSize + Sm4BlockSize);
        var ciphertext = new byte[ciphertextLen];
        var expectedMac = new byte[HmacSm3Output];
        Array.Copy(raw, SaltSize + Sm4BlockSize, ciphertext, 0, ciphertextLen);
        Array.Copy(raw, macStart, expectedMac, 0, HmacSm3Output);

        var dk = DeriveSmKey(password, salt, iterations, Sm4CbcDkLen);
        var encKey = new byte[Sm4KeySize];
        var macKey = new byte[HmacSm3Output];
        Array.Copy(dk, 0, encKey, 0, Sm4KeySize);
        Array.Copy(dk, Sm4KeySize, macKey, 0, HmacSm3Output);

        try
        {
            if (!ConstantTimeEquals(ComputeHmacSm3(macKey, iv, ciphertext), expectedMac))
                throw new NasyptException(NasyptError.DecryptionFailed);

            var plaintext = Sm4CbcProcess(false, encKey, iv, ciphertext);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (InvalidCipherTextException ex)
        {
            throw new NasyptException(NasyptError.DecryptionFailed, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dk);
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    private static byte[] Sm4CbcProcess(bool forEncryption, byte[] key, byte[] iv, byte[] data)
    {
        var cipher = new PaddedBufferedBlockCipher(
            new CbcBlockCipher(new SM4Engine()), new Pkcs7Padding());
        cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        var output = new byte[cipher.GetOutputSize(data.Length)];
        var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        len += cipher.DoFinal(output, len);
        var result = new byte[len];
        Array.Copy(output, 0, result, 0, len);
        return result;
    }

    // ── HMAC-SM3 ─────────────────────────────────────────────────────

    private static byte[] ComputeHmacSm3(byte[] key, params byte[][] dataParts)
    {
        var hmac = new HMac(new SM3Digest());
        hmac.Init(new KeyParameter(key));
        foreach (var part in dataParts)
            hmac.BlockUpdate(part, 0, part.Length);
        var mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);
        return mac;
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;
        var result = 0;
        for (var i = 0; i < a.Length; i++)
            result |= a[i] ^ b[i];
        return result == 0;
    }
}
