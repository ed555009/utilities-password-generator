using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Models.Responses;
using Utilities.PasswordGenerator.Services;

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
	public string Generate(int length = 8,
		int requiredUppercase = 1,
		int requiredLowercase = 1,
		int requiredNumeric = 1,
		int requiredSpecialChar = 1,
		string? specialChars = PasswordGeneratorService.DefaultSpecialChars);

	/// <summary>
	/// Hashes the specified password with PBKDF2-HMAC-SHA512.
	/// </summary>
	/// <param name="password">The password to hash.</param>
	/// <returns>The hash, the salt and the iteration count. The result does not contain the password.</returns>
	public HashedPasswordModel Hash(string password);

	/// <summary>
	/// Verifies the specified password against the stored hash.
	/// </summary>
	/// <param name="data">The password, the stored hash, the stored salt and the stored iteration count.</param>
	/// <returns>True if the password matches the hash, false otherwise.</returns>
	public bool Verify(VerifyPasswordModel data);

	/// <summary>
	/// Gets a value that shows if the stored hash uses parameters older than the current parameters.
	/// </summary>
	/// <param name="data">The stored values of the hash.</param>
	/// <returns>True if the caller must compute a new hash with <see cref="Hash"/> after a successful <see cref="Verify"/>.</returns>
	public bool NeedsRehash(VerifyPasswordModel data);
}
