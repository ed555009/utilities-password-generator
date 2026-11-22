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
	/// <exception cref="ArgumentOutOfRangeException">Thrown when the password length is less than 8 or greater than 32.</exception>
	/// <exception cref="ArgumentException">Thrown when the password length is less than the total number of required characters.</exception>
	public string Generate(
		int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = DefaultSpecialChars)
	{
		int totalRequired = requiredUppercase + requiredLowercase + requiredNumeric + requiredSpecialChar;

		if (length < 8 || length > 32)
			throw new ArgumentOutOfRangeException(nameof(length), "Password length must be between 8 and 32 characters");

		if (length < totalRequired)
			throw new ArgumentException($"Password length must be at least {totalRequired}");

		const string upperCase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
		const string lowerCase = "abcdefghijkmnopqrstuvwxyz";
		const string numeric = "23456789";

		if (specialChars == null || specialChars.Length == 0)
			requiredSpecialChar = 0;

		StringBuilder password = new StringBuilder();

		// ensure the password contains at least X of each type of character
		for (int i = 0; i < requiredUppercase; i++)
			password.Append(upperCase[GetRandomNumber(upperCase.Length)]);

		for (int i = 0; i < requiredLowercase; i++)
			password.Append(lowerCase[GetRandomNumber(lowerCase.Length)]);

		for (int i = 0; i < requiredNumeric; i++)
			password.Append(numeric[GetRandomNumber(numeric.Length)]);

		if (specialChars != null)
			for (int i = 0; i < requiredSpecialChar; i++)
				password.Append(specialChars[GetRandomNumber(specialChars.Length)]);

		// fill the rest of the password length with a random mix of all categories
		string allChars = upperCase + lowerCase + numeric + specialChars;
		int requiredChars = requiredUppercase + requiredLowercase + requiredNumeric + requiredSpecialChar;

		for (int i = requiredChars; i < length; i++)
			password.Append(allChars[GetRandomNumber(allChars.Length)]);

		// shuffle the password
		return new string(password.ToString().OrderBy(_ => GetRandomNumber(int.MaxValue)).ToArray());
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
	/// netstandard2.1 does not contain the one-shot method Rfc2898DeriveBytes.Pbkdf2. The result is the same.
	/// </remarks>
	private static byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int hashSize)
	{
		using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, _hashAlgorithm);

		return pbkdf2.GetBytes(hashSize);
	}

	/// <summary>
	/// Gets a random number from 0 to <paramref name="max"/> - 1.
	/// </summary>
	/// <param name="max">The exclusive upper bound.</param>
	/// <returns>A random number.</returns>
	private static int GetRandomNumber(int max) =>
		RandomNumberGenerator.GetInt32(max);
}
