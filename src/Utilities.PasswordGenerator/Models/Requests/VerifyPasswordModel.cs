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
}
