using System.Security.Cryptography;
using System.Text;
using Utilities.PasswordGenerator.Interfaces;
using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Models.Responses;

namespace Utilities.PasswordGenerator.Services;

/// <summary>
/// Service class for generating passwords.
/// </summary>
public class PasswordGeneratorService : IPasswordGeneratorService
{
	private readonly int _keySize = 128;
	private readonly int _iterations = 12_800;
	private readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA512;

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
		string? specialChars = "!@#$%^*()-_=+?")
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
	/// Generates a hashed password with the specified requirements.
	/// </summary>
	/// <param name="length">The length of the password (default is 8).</param>
	/// <param name="requiredUppercase">The minimum number of uppercase characters required (default is 1).</param>
	/// <param name="requiredLowercase">The minimum number of lowercase characters required (default is 1).</param>
	/// <param name="requiredNumeric">The minimum number of numeric characters required (default is 1).</param>
	/// <param name="requiredSpecialChar">The minimum number of special characters required (default is 1).</param>
	/// <param name="specialChars">The special characters to include in the password (default is "!@#$%^*()-_=+?").</param>
	/// <returns>A hashed password model containing the hashed password and salt.</returns>
	public HashedPasswordModel GenerateHashed(
		int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = "!@#$%^*()-_=+?") =>
			Hash(Generate(
					length,
					requiredUppercase,
					requiredLowercase,
					requiredNumeric,
					requiredSpecialChar,
					specialChars));

	/// <summary>
	/// Hashes the specified password using PBKDF2 algorithm.
	/// </summary>
	/// <param name="password">The password to hash.</param>
	/// <returns>A hashed password model containing the hashed password and salt.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the password is null.</exception>
	public HashedPasswordModel Hash(string? password)
	{
		ArgumentNullException.ThrowIfNull(password);

		var saltByte = RandomNumberGenerator.GetBytes(_keySize);
		var hash = Rfc2898DeriveBytes.Pbkdf2(
			Encoding.UTF8.GetBytes(password),
			saltByte,
			_iterations,
			_hashAlgorithm,
			_keySize);

		return new HashedPasswordModel
		{
			Hash = Convert.ToHexString(hash),
			Salt = Convert.ToHexString(saltByte)
		};
	}

	/// <summary>
	/// Verifies the specified password against the hashed password model.
	/// </summary>
	/// <param name="data">The hashed password model containing the password, salt, and hash.</param>
	/// <returns>True if the password is verified, false otherwise.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the password, salt, or hash in the hashed password model is null.</exception>
	public bool Verify(VerifyPasswordModel data)
	{
		ArgumentNullException.ThrowIfNull(data.Password);
		ArgumentNullException.ThrowIfNull(data.Salt);
		ArgumentNullException.ThrowIfNull(data.Hash);

		var comparer = Rfc2898DeriveBytes.Pbkdf2(
			data.Password,
			Convert.FromHexString(data.Salt),
			_iterations,
			_hashAlgorithm,
			_keySize);

		return comparer.SequenceEqual(Convert.FromHexString(data.Hash));
	}

	static int GetRandomNumber(int max) =>
		Math.Abs(BitConverter.ToInt32(RandomNumberGenerator.GetBytes(4), 0) % max);
}
