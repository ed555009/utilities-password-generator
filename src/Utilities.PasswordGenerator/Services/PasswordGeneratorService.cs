using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Utilities.PasswordGenerator.Interfaces;

namespace Utilities.PasswordGenerator.Services
{
	/// <summary>
	/// Service class for generating passwords.
	/// </summary>
	public class PasswordGeneratorService : IPasswordGeneratorService
	{
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
		public string Generate(int length = 8,
			int requiredUppercase = 1,
			int requiredLowercase = 1,
			int requiredNumeric = 1,
			int requiredSpecialChar = 1,
			string specialChars = "!@#$%^*()-_=+?")
		{
			int totalRequired = requiredUppercase + requiredLowercase + requiredNumeric + requiredSpecialChar;

			if (length < 8 || length > 32)
				throw new ArgumentOutOfRangeException(nameof(length), "Password length must be between 8 and 32 characters");

			if (length < totalRequired)
				throw new ArgumentException($"Password length must be at least {totalRequired}");

			const string upperCase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
			const string lowerCase = "abcdefghijkmnopqrstuvwxyz";
			const string numeric = "23456789";

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
			return new string(password.ToString().OrderBy(_ => GetRandomNumber(int.MaxValue)).ToArray());
		}

		int GetRandomNumber(int max)
		{
			using (var rng = new RNGCryptoServiceProvider())
			{
				byte[] data = new byte[4];
				rng.GetBytes(data);
				int value = BitConverter.ToInt32(data, 0);
				return Math.Abs(value % max);
			}
		}
	}
}
