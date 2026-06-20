using System.CommandLine;
using System.CommandLine.Invocation;
using NasyptLite;

const int MinRecommendedPasswordLength = 8;

var algorithmOption = new Option<string>(
    "--algorithm",
    "-a",
    "--alg")
{
    Description = "Encryption algorithm to use.",
    Required = false
};

var iterationsOption = new Option<int?>(
    "--iterations")
{
    Description = "Override the PBKDF2 iteration count.",
    Required = false
};

var passwordOption = new Option<string>(
    "--password",
    "-p")
{
    Description = "Password for key derivation.",
    Required = true
};

var inputOption = new Option<string>(
    "--input",
    "-i")
{
    Description = "The plaintext to encrypt or the Base64/ENC(...) ciphertext to decrypt.",
    Required = true
};

var wrapOption = new Option<bool>(
    "--wrap")
{
    Description = "Wrap the output in ENC(...).",
    Required = false
};

var quietOption = new Option<bool>(
    "--quiet",
    "-q")
{
    Description = "Suppress password-strength warnings.",
    Required = false
};

var rootCommand = new RootCommand("nasypt-lite: Jasypt-compatible encryption/decryption for .NET");

var encryptCommand = new Command("encrypt", "Encrypt a plaintext value.");
encryptCommand.Add(inputOption);
encryptCommand.Add(passwordOption);
encryptCommand.Add(algorithmOption);
encryptCommand.Add(iterationsOption);
encryptCommand.Add(wrapOption);
encryptCommand.Add(quietOption);
encryptCommand.SetAction(HandleEncrypt);

var decryptCommand = new Command("decrypt", "Decrypt a ciphertext or ENC(...)-wrapped value.");
decryptCommand.Add(inputOption);
decryptCommand.Add(passwordOption);
decryptCommand.Add(algorithmOption);
decryptCommand.Add(iterationsOption);
decryptCommand.Add(quietOption);
decryptCommand.SetAction(HandleDecrypt);

rootCommand.Add(encryptCommand);
rootCommand.Add(decryptCommand);

var parseResult = rootCommand.Parse(args);
return parseResult.Invoke(new InvocationConfiguration());

static void WarnShortPassword(string password, bool quiet)
{
    if (quiet)
        return;

    var charCount = password.EnumerateRunes().Count();
    if (charCount >= MinRecommendedPasswordLength)
        return;

    Console.Error.WriteLine(
        $"Warning: password length is below the recommended {MinRecommendedPasswordLength} characters; continuing anyway. Use --quiet to suppress this warning.");
}

static Algorithm ParseAlgorithm(string? alg)
{
    if (alg is null)
        return Algorithm.PBEWithHMACSHA512AndAES_256;

    if (!Enum.TryParse<Algorithm>(alg, true, out var result))
        throw new NasyptException(NasyptError.UnknownAlgorithm);
    return result;
}

static void HandleEncrypt(ParseResult parseResult)
{
    var input = parseResult.GetRequiredValue<string>("--input");
    var password = parseResult.GetRequiredValue<string>("--password");
    var algorithm = parseResult.GetValue<string?>("--algorithm");
    var iterations = parseResult.GetValue<int?>("--iterations");
    var wrap = parseResult.GetValue<bool>("--wrap");
    var quiet = parseResult.GetValue<bool>("--quiet");

    WarnShortPassword(password, quiet);

    try
    {
        var alg = ParseAlgorithm(algorithm);
        var result = Nasypt.EncryptWith(alg, password, input, iterations);

        if (wrap)
        {
            if (alg == Algorithm.PBEWithHMACSHA512AndAES_256)
            {
                result = $"ENC({result})";
            }
            else
            {
                Console.Error.WriteLine("Warning: --wrap is only supported with the default algorithm; output not wrapped.");
            }
        }

        Console.WriteLine(result);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Encryption failed: {ex.Message}");
        Environment.Exit(1);
    }
}

static void HandleDecrypt(ParseResult parseResult)
{
    var input = parseResult.GetRequiredValue<string>("--input");
    var password = parseResult.GetRequiredValue<string>("--password");
    var algorithm = parseResult.GetValue<string?>("--algorithm");
    var iterations = parseResult.GetValue<int?>("--iterations");
    var quiet = parseResult.GetValue<bool>("--quiet");

    WarnShortPassword(password, quiet);

    try
    {
        var alg = ParseAlgorithm(algorithm);

        if (alg == Algorithm.PBEWithHMACSHA512AndAES_256 && Nasypt.IsEncValue(input))
        {
            var result = Nasypt.DecryptEnc(input, password);
            Console.WriteLine(result);
        }
        else
        {
            var result = Nasypt.DecryptWith(alg, password, input, iterations);
            Console.WriteLine(result);
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Decryption failed: {ex.Message}");
        Environment.Exit(1);
    }
}
