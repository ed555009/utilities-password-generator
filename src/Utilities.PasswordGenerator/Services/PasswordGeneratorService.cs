using System.Security.Cryptography;
using System.Text;
using Utilities.PasswordGenerator.Interfaces;
using Utilities.PasswordGenerator.Internal;
using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Models.Responses;

namespace Utilities.PasswordGenerator.Services;

/// <summary>
/// Service class for generating passwords.
/// </summary>
public sealed class PasswordGeneratorService : IPasswordGeneratorService
{
	/// <summary>
	/// The default special characters of <see cref="Generate"/>.
	/// </summary>
	public const string DefaultSpecialChars = "!@#$%^*()-_=+?";

	// Use the OWASP value for PBKDF2-HMAC-SHA512.
	private const int Iterations = 210_000;

	private const int SaltSize = 16;

	// Use the SHA-512 output size. A longer output makes the defender compute more blocks than the attacker.
	private const int HashSize = 64;

	// Hashes from version 6.0.x have no iteration count. Verify them with the 6.0.x parameters.
	private const int LegacyIterations = 12_800;
	private const int LegacyHashSize = 128;

	// Reject larger values. Verify must not run an expensive computation for an attacker.
	private const int MaxIterations = 1_000_000;
	private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA512;

	/// <summary>
	/// Generates a password with the specified requirements.
	/// </summary>
	/// <param name="length">The length of the password (default is 8).</param>
	/// <param name="requiredUppercase">The minimum number of uppercase characters required (default is 1).</param>
	/// <param name="requiredLowercase">The minimum number of lowercase characters required (default is 1).</param>
	/// <param name="requiredNumeric">The minimum number of numeric characters required (default is 1).</param>
	/// <param name="requiredSpecialChar">The minimum number of special characters required (default is 1).</param>
	/// <param name="specialChars">The special characters to include in the password (default is "!@#$%^*()-_=+?").</param>
	/// <returns>A randomly generated password.</returns>
	/// <remarks>
	/// <paramref name="specialChars"/> must not contain letters, digits, white space, control characters or surrogates.
	/// Generate removes duplicate characters from <paramref name="specialChars"/>.
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the password length is less than 8 or greater than 32, or a required count is negative.</exception>
	/// <exception cref="ArgumentException">Thrown when the password length is less than the total number of required characters, or <paramref name="specialChars"/> contains a character that is not allowed.</exception>
	public string Generate(
		int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = DefaultSpecialChars)
	{
		ThrowIfNegative(requiredUppercase, nameof(requiredUppercase));
		ThrowIfNegative(requiredLowercase, nameof(requiredLowercase));
		ThrowIfNegative(requiredNumeric, nameof(requiredNumeric));
		ThrowIfNegative(requiredSpecialChar, nameof(requiredSpecialChar));

		int totalRequired = requiredUppercase + requiredLowercase + requiredNumeric + requiredSpecialChar;

		if (length < 8 || length > 32)
			throw new ArgumentOutOfRangeException(nameof(length), "Password length must be between 8 and 32 characters");

		if (length < totalRequired)
			throw new ArgumentException($"Password length must be at least {totalRequired}");

		const string upperCase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
		const string lowerCase = "abcdefghijkmnopqrstuvwxyz";
		const string numeric = "23456789";

		specialChars = NormalizeSpecialChars(specialChars);

		if (specialChars.Length == 0)
			requiredSpecialChar = 0;

		StringBuilder password = new StringBuilder();

		// ensure the password contains at least X of each type of character
		for (int i = 0; i < requiredUppercase; i++)
			password.Append(upperCase[GetRandomNumber(upperCase.Length)]);

		for (int i = 0; i < requiredLowercase; i++)
			password.Append(lowerCase[GetRandomNumber(lowerCase.Length)]);

		for (int i = 0; i < requiredNumeric; i++)
			password.Append(numeric[GetRandomNumber(numeric.Length)]);

		for (int i = 0; i < requiredSpecialChar; i++)
			password.Append(specialChars[GetRandomNumber(specialChars.Length)]);

		// fill the rest of the password length with a random mix of all categories
		string allChars = upperCase + lowerCase + numeric + specialChars;
		int requiredChars = requiredUppercase + requiredLowercase + requiredNumeric + requiredSpecialChar;

		for (int i = requiredChars; i < length; i++)
			password.Append(allChars[GetRandomNumber(allChars.Length)]);

		// shuffle the password
		var chars = password.ToString().ToCharArray();
		Shuffle(chars);

		return new string(chars);
	}

	/// <summary>
	/// Throws when a required character count is negative.
	/// </summary>
	/// <param name="value">The count.</param>
	/// <param name="paramName">The parameter name of the count.</param>
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the count is negative.</exception>
	private static void ThrowIfNegative(int value, string paramName)
	{
		// A negative count decreases the required total and makes the password longer than the length.
		if (value < 0)
			throw new ArgumentOutOfRangeException(paramName, value, "The count must be 0 or more.");
	}

	/// <summary>
	/// Validates the special characters and removes duplicates.
	/// </summary>
	/// <param name="specialChars">The special characters. Null or empty means no special characters.</param>
	/// <returns>The special characters without duplicates, or an empty string.</returns>
	/// <exception cref="ArgumentException">Thrown when a character is a letter, a digit, white space, a control character or a surrogate.</exception>
	private static string NormalizeSpecialChars(string? specialChars)
	{
		if (string.IsNullOrEmpty(specialChars))
			return string.Empty;

		// Reject letters and digits. They can add the ambiguous characters 0 O 1 I l.
		// Reject surrogates. Generate selects 1 char at a time and splits a surrogate pair.
		if (specialChars.Any(c => char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || char.IsControl(c) || char.IsSurrogate(c)))
			throw new ArgumentException("Special characters must not contain letters, digits, white space, control characters or surrogates.", nameof(specialChars));

		// Remove duplicates. A duplicate character has a higher probability than the other characters.
		return new string(specialChars.Distinct().ToArray());
	}

	/// <summary>
	/// Shuffles the characters in place with the Fisher-Yates algorithm.
	/// </summary>
	/// <param name="chars">The characters to shuffle.</param>
	private static void Shuffle(char[] chars)
	{
		for (var i = chars.Length - 1; i > 0; i--)
		{
			var j = GetRandomNumber(i + 1);
			(chars[i], chars[j]) = (chars[j], chars[i]);
		}
	}

	/// <summary>
	/// Hashes the specified password with PBKDF2-HMAC-SHA512.
	/// </summary>
	/// <param name="password">The password to hash.</param>
	/// <returns>The hash, the salt and the iteration count. Store all 3 values.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the password is null.</exception>
	public HashedPasswordModel Hash(string password)
	{
		if (password is null)
			throw new ArgumentNullException(nameof(password));

		var saltByte = new byte[SaltSize];
		RandomNumberGenerator.Fill(saltByte);
		var hash = DeriveKey(Encoding.UTF8.GetBytes(password), saltByte, Iterations, HashSize);

		return new HashedPasswordModel
		{
			Hash = HexConverter.ToHexString(hash),
			Salt = HexConverter.ToHexString(saltByte),
			Iterations = Iterations
		};
	}

	/// <summary>
	/// Verifies the specified password against the stored hash.
	/// </summary>
	/// <param name="data">The password, the stored hash, the stored salt and the stored iteration count.</param>
	/// <returns>True if the password matches the hash, false otherwise.</returns>
	/// <remarks>
	/// Set <see cref="VerifyPasswordModel.Iterations"/> to null for a hash from version 6.0.x.
	/// </remarks>
	/// <exception cref="ArgumentNullException">Thrown when the data, or the password, salt or hash in the data, is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the iteration count is not null and not from 210,000 to 1,000,000.</exception>
	/// <exception cref="ArgumentException">Thrown when the hash length does not match the iteration count.</exception>
	/// <exception cref="FormatException">Thrown when the hash or the salt is not a hex string.</exception>
	public bool Verify(VerifyPasswordModel data)
	{
		if (data is null)
			throw new ArgumentNullException(nameof(data));

		if (data.Password is null)
			throw new ArgumentNullException(nameof(data.Password));

		if (data.Salt is null)
			throw new ArgumentNullException(nameof(data.Salt));

		if (data.Hash is null)
			throw new ArgumentNullException(nameof(data.Hash));

		var (iterations, hashSize) = SelectParameters(data.Iterations);
		var expected = HexConverter.FromHexString(data.Hash);

		if (expected.Length != hashSize)
			throw new ArgumentException($"The hash must be {hashSize} bytes.", nameof(data));

		var actual = DeriveKey(Encoding.UTF8.GetBytes(data.Password), HexConverter.FromHexString(data.Salt), iterations, hashSize);

		// Compare in fixed time. SequenceEqual stops at the first different byte and leaks the matching prefix length.
		return CryptographicOperations.FixedTimeEquals(actual, expected);
	}

	/// <summary>
	/// Gets a value that shows if the stored hash uses parameters older than the current parameters.
	/// </summary>
	/// <param name="data">The stored values of the hash.</param>
	/// <returns>True if the caller must compute a new hash with <see cref="Hash"/> after a successful <see cref="Verify"/>.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the data is null.</exception>
	public bool NeedsRehash(VerifyPasswordModel data)
	{
		if (data is null)
			throw new ArgumentNullException(nameof(data));

		return data.Iterations is null || data.Iterations < Iterations;
	}

	/// <summary>
	/// Selects the PBKDF2 parameters for the stored iteration count.
	/// </summary>
	/// <param name="iterations">The stored iteration count. Null means a hash from version 6.0.x.</param>
	/// <returns>The iteration count and the hash size in bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the iteration count is not null and not from 210,000 to 1,000,000.</exception>
	private static (int Iterations, int HashSize) SelectParameters(int? iterations)
	{
		if (iterations is null)
			return (LegacyIterations, LegacyHashSize);

		if (iterations < Iterations || iterations > MaxIterations)
			throw new ArgumentOutOfRangeException(nameof(VerifyPasswordModel.Iterations), iterations, $"The iteration count must be from {Iterations} to {MaxIterations}.");

		return (iterations.Value, HashSize);
	}

	/// <summary>
	/// Derives the PBKDF2 key of the password with the salt.
	/// </summary>
	/// <param name="password">The UTF-8 bytes of the password.</param>
	/// <param name="salt">The salt.</param>
	/// <param name="iterations">The iteration count.</param>
	/// <param name="hashSize">The output size in bytes.</param>
	/// <returns>The derived key.</returns>
	/// <remarks>
	/// The net10.0 assembly calls the one-shot method. The netstandard2.1 assembly uses the constructor. Both return the same bytes.
	/// </remarks>
	private static byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int hashSize)
	{
#if NET
		// Use the one-shot method. It calls the platform crypto library and takes about 37% of the time.
		return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, _hashAlgorithm, hashSize);
#else
		// netstandard2.1 does not contain the one-shot method.
		using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, _hashAlgorithm);

		return pbkdf2.GetBytes(hashSize);
#endif
	}

	/// <summary>
	/// Gets a random number from 0 to <paramref name="max"/> - 1.
	/// </summary>
	/// <param name="max">The exclusive upper bound.</param>
	/// <returns>A random number.</returns>
	private static int GetRandomNumber(int max) =>
		RandomNumberGenerator.GetInt32(max);
}
