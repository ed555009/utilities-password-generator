using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Models.Responses;

namespace Utilities.PasswordGenerator.Interfaces;

/// <summary>
/// Represents a service for generating passwords.
/// </summary>
public interface IPasswordGeneratorService
{
	/// <summary>
	/// Generates a password with the specified requirements.
	/// </summary>
	/// <param name="length">The length of the password.</param>
	/// <param name="requiredUppercase">The minimum number of uppercase characters required in the password.</param>
	/// <param name="requiredLowercase">The minimum number of lowercase characters required in the password.</param>
	/// <param name="requiredNumeric">The minimum number of numeric characters required in the password.</param>
	/// <param name="requiredSpecialChar">The minimum number of special characters required in the password.</param>
	/// <param name="specialChars">The special characters allowed in the password.</param>
	/// <returns>A randomly generated password.</returns>
	string Generate(int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = "!@#$%^*()-_=+?");

	/// <summary>
	/// Generates a hashed password with the specified requirements.
	/// </summary>
	/// <param name="length">The length of the password.</param>
	/// <param name="requiredUppercase">The minimum number of uppercase characters required in the password.</param>
	/// <param name="requiredLowercase">The minimum number of lowercase characters required in the password.</param>
	/// <param name="requiredNumeric">The minimum number of numeric characters required in the password.</param>
	/// <param name="requiredSpecialChar">The minimum number of special characters required in the password.</param>
	/// <param name="specialChars">The special characters allowed in the password.</param>
	/// <returns>A hashed password model containing the hashed password and the original password.</returns>
	HashedPasswordModel GenerateHashed(int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = "!@#$%^*()-_=+?");

	/// <summary>
	/// Hashes the specified password.
	/// </summary>
	/// <param name="password">The password to hash.</param>
	/// <returns>A hashed password model containing the hashed password and the original password.</returns>
	HashedPasswordModel Hash(string? password);

	/// <summary>
	/// Verifies the specified password against the hashed password.
	/// </summary>
	/// <param name="data">The verify password model containing the hashed password and the password to verify.</param>
	/// <returns>True if the password is verified, false otherwise.</returns>
	bool Verify(VerifyPasswordModel data);
}
