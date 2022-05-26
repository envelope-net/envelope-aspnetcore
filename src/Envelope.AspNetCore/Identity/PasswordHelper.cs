using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Envelope.Extensions;
using System.Security.Cryptography;

namespace Envelope.AspNetCore.Identity;

public static class PasswordHelper
{
	public static byte[] GenerateRandomSalt(int saltLengthInBits = 128)
	{
		if (saltLengthInBits <= 0)
			throw new ArgumentOutOfRangeException(nameof(saltLengthInBits));

		if (saltLengthInBits % 8 != 0)
			throw new ArgumentException($"{nameof(saltLengthInBits)} = {saltLengthInBits} must be divisible by 8", nameof(saltLengthInBits));

		byte[] salt = new byte[saltLengthInBits / 8];
		using (var rng = RandomNumberGenerator.Create())
			rng.GetBytes(salt);

		return salt;
	}

	public static string GenerateRandomSaltAsBase64(int saltLengthInBits = 128)
		=> Convert.ToBase64String(GenerateRandomSalt(saltLengthInBits));

	public static string SaltToBase64(byte[] salt)
		=> Convert.ToBase64String(salt ?? throw new ArgumentNullException(nameof(salt)));

	public static byte[] CreatePasswordHash(
		string password,
		byte[] salt,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
		=> KeyDerivation.Pbkdf2(
			password: password ?? throw new ArgumentNullException(nameof(password)),
			salt: salt ?? throw new ArgumentNullException(nameof(salt)),
			prf: pseudoRandomFunction,
			iterationCount: iterationCount,
			numBytesRequested: numBytesRequested);

	public static byte[] CreatePasswordHash(
		string password,
		out byte[] salt,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */ )
		=> CreatePasswordHash(
			password: password ?? throw new ArgumentNullException(nameof(password)),
			salt: salt = GenerateRandomSalt(128),
			pseudoRandomFunction: pseudoRandomFunction,
			iterationCount: iterationCount,
			numBytesRequested: numBytesRequested);

	public static string CreatePasswordHashAsBase64(
		string password,
		byte[] salt,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
		=> Convert.ToBase64String(
			KeyDerivation.Pbkdf2(
				password: password ?? throw new ArgumentNullException(nameof(password)),
				salt: salt ?? throw new ArgumentNullException(nameof(salt)),
				prf: pseudoRandomFunction,
				iterationCount: iterationCount,
				numBytesRequested: numBytesRequested));

	public static string CreatePasswordHashAsBase64(
		string password,
		out byte[] salt,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
		=> CreatePasswordHashAsBase64(
			password: password ?? throw new ArgumentNullException(nameof(password)),
			salt: salt = GenerateRandomSalt(128),
			pseudoRandomFunction: pseudoRandomFunction,
			iterationCount: iterationCount,
			numBytesRequested: numBytesRequested);

	public static string CreatePasswordHashAsBase64(
		string password,
		out string saltBase64,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
	{
		var salt = GenerateRandomSalt(128);
		saltBase64 = Convert.ToBase64String(salt);

		return CreatePasswordHashAsBase64(
			password: password ?? throw new ArgumentNullException(nameof(password)),
			salt: salt,
			pseudoRandomFunction: pseudoRandomFunction,
			iterationCount: iterationCount,
			numBytesRequested: numBytesRequested);
	}

	public static bool VerifyHashedPassword(
		string? originalPasswordHash, //base64
		byte[]? salt,
		string? password,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
	{
		if (originalPasswordHash == null || salt == null || password == null)
			return false;

		var hashedPassword = CreatePasswordHashAsBase64(
			password,
			salt,
			pseudoRandomFunction,
			iterationCount,
			numBytesRequested);
		return originalPasswordHash == hashedPassword;
	}

	public static bool VerifyHashedPassword(
		string? originalPasswordHash, //base64
		string? salt,
		string? password,
		KeyDerivationPrf pseudoRandomFunction = KeyDerivationPrf.HMACSHA256,
		int iterationCount = 10000,
		int numBytesRequested = 32 /* 256 / 8 */)
		=> VerifyHashedPassword(
			originalPasswordHash,
			salt == null
				? null
				: Convert.FromBase64String(salt),
			password,
			pseudoRandomFunction,
			iterationCount,
			numBytesRequested);

	private readonly static char[] _lowercaseChars = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
	private readonly static char[] _uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
	private readonly static char[] _numbers = "0123456789".ToCharArray();

	public static PasswordStatistics GetPasswordStatistics(string password, List<string> forbiddenPhrases)
	{
		var result = new PasswordStatistics();

		if (string.IsNullOrEmpty(password))
			return result;

		var passWithoutAccent = password.RemoveAccents();

		if (forbiddenPhrases != null)
		{
			var lowerPassWithoutAccent = passWithoutAccent.ToLower();
			foreach (var phrase in forbiddenPhrases.Where(x => !string.IsNullOrEmpty(x)))
			{
				var phraseWithoutAccent = phrase.RemoveAccents().ToLower();
				if (lowerPassWithoutAccent.Contains(phraseWithoutAccent))
					result.SetContainsForbiddenPhrases();
			}
		}

		SetCharStatistics(passWithoutAccent[0], result);
		var previousChar = password[0];

		var charsDict = new Dictionary<char, int>
		{
			[previousChar] = 1
		};

		result.MaxEqualCharactersSequence = 1;
		var currentCharCount = 1;

		for (int i = 1; i < passWithoutAccent.Length; i++)
		{
			var currentChar = password[i];
			SetCharStatistics(passWithoutAccent[i], result);

			if (charsDict.TryGetValue(currentChar, out int count))
				charsDict[currentChar] = count + 1;
			else
				charsDict[currentChar] = 1;

			if (previousChar.Equals(currentChar))
			{
				currentCharCount++;
			}
			else
			{
				if (result.MaxEqualCharactersSequence < currentCharCount)
					result.MaxEqualCharactersSequence = currentCharCount;

				currentCharCount = 1;
			}

			previousChar = currentChar;
		}

		if (result.MaxEqualCharactersSequence < currentCharCount)
			result.MaxEqualCharactersSequence = currentCharCount;

		result.MaxCharacterFrequency = charsDict.Values.Max();

		return result;
	}

	private static PasswordStatistics SetCharStatistics(char ch, PasswordStatistics stats)
	{
		stats.Length++;

		if (_lowercaseChars.Contains(ch))
			return stats.IncrementLowercaseCharactersCount();

		if (_uppercaseChars.Contains(ch))
			return stats.IncrementUpperCharactersCount();

		if (_numbers.Contains(ch))
			return stats.IncrementNumbersCount();

		return stats.IncrementSpecialCharactersCount();
	}
}

public class PasswordStatistics
{
	public bool ContainsForbiddenPhrases { get; set; }
	public int Length { get; set; }
	public int LowercaseCharactersCount { get; set; }
	public int UpperCharactersCount { get; set; }
	public int NumbersCount { get; set; }
	public int SpecialCharactersCount { get; set; }
	public int MaxEqualCharactersSequence { get; set; }
	public int MaxCharacterFrequency { get; set; }

	internal PasswordStatistics IncrementLowercaseCharactersCount()
	{
		LowercaseCharactersCount++;
		return this;
	}

	internal PasswordStatistics IncrementUpperCharactersCount()
	{
		UpperCharactersCount++;
		return this;
	}

	internal PasswordStatistics IncrementNumbersCount()
	{
		NumbersCount++;
		return this;
	}

	internal PasswordStatistics IncrementSpecialCharactersCount()
	{
		SpecialCharactersCount++;
		return this;
	}

	internal PasswordStatistics SetContainsForbiddenPhrases()
	{
		ContainsForbiddenPhrases = true;
		return this;
	}
}
