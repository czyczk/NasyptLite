namespace NasyptLite;

/// <summary>Error codes returned by <see cref="NasyptException"/>.</summary>
public enum NasyptError
{
    /// <summary>Ciphertext is too short to contain the required salt and IV.</summary>
    CiphertextTooShort,
    /// <summary>The input could not be decoded from Base64.</summary>
    FailedToDecodeBase64,
    /// <summary>Decryption failed. Check password or ciphertext integrity.</summary>
    DecryptionFailed,
    /// <summary>The value is not wrapped in ENC(…).</summary>
    NotEncValue,
    /// <summary>The specified algorithm name is not recognised.</summary>
    UnknownAlgorithm,
    /// <summary>The PBKDF2 iteration count must be greater than zero.</summary>
    InvalidIterations
}
