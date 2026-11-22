namespace Utilities.PasswordGenerator.Models.Requests;

/// <summary>
/// Represents a password and the stored hash and salt to verify the password against.
/// </summary>
public sealed class VerifyPasswordModel
{
	/// <summary>
	/// Gets or sets the password to verify.
	/// </summary>
	public string? Password { get; set; }

	/// <summary>
	/// Gets or sets the stored hash as a hex string.
	/// </summary>
	public string? Hash { get; set; }

	/// <summary>
	/// Gets or sets the stored salt as a hex string.
	/// </summary>
	public string? Salt { get; set; }

	/// <summary>
	/// Gets or sets the stored PBKDF2 iteration count.
	/// </summary>
	/// <remarks>
	/// Set the value to null for a hash from version 6.0.x. Verify then uses the 6.0.x parameters.
	/// </remarks>
	public int? Iterations { get; set; }
}
