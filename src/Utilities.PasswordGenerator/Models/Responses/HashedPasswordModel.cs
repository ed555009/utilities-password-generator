namespace Utilities.PasswordGenerator.Models.Responses;

/// <summary>
/// Represents a hashed password and the salt used to compute the hash.
/// </summary>
public sealed class HashedPasswordModel
{
	/// <summary>
	/// Gets or sets the hash as an uppercase hex string.
	/// </summary>
	public string Hash { get; set; } = string.Empty;

	/// <summary>
	/// Gets or sets the salt as an uppercase hex string.
	/// </summary>
	public string Salt { get; set; } = string.Empty;

	/// <summary>
	/// Gets or sets the PBKDF2 iteration count used to compute the hash.
	/// </summary>
	public int Iterations { get; set; }
}
