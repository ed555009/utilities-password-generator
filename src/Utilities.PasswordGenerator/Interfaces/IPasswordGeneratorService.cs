namespace Utilities.PasswordGenerator.Interfaces
{
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
			string specialChars = "!@#$%^*()-_=+?");
	}
}
