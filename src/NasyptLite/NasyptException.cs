namespace NasyptLite;

/// <summary>Exception thrown by all nasypt-lite operations.</summary>
public class NasyptException : Exception
{
    /// <summary>The categorised error code.</summary>
    public NasyptError ErrorCode { get; }

    /// <summary>Creates an exception with the given error code.</summary>
    public NasyptException(NasyptError error)
        : base(ErrorMessage(error))
    {
        ErrorCode = error;
    }

    /// <summary>Creates an exception that wraps an inner exception.</summary>
    public NasyptException(NasyptError error, Exception inner)
        : base(ErrorMessage(error), inner)
    {
        ErrorCode = error;
    }

    private static string ErrorMessage(NasyptError error)
    {
        return error switch
        {
            NasyptError.CiphertextTooShort => "Ciphertext is too short to contain salt and IV.",
            NasyptError.FailedToDecodeBase64 => "Failed to decode the Base64-encoded input.",
            NasyptError.DecryptionFailed => "Decryption failed. Check your password or the integrity of the ciphertext.",
            NasyptError.NotEncValue => "The value is not an ENC(...)-wrapped string.",
            NasyptError.UnknownAlgorithm => "The specified algorithm is unknown or not supported.",
            NasyptError.InvalidIterations => "The iteration count must be greater than zero.",
            _ => "An unknown error occurred."
        };
    }
}
