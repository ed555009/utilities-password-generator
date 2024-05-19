namespace Utilities.PasswordGenerator.Models.Responses;

/// <summary>
/// Represents a model for a hashed password.
/// </summary>
public class HashedPasswordModel : SaltModel
{
	/// <summary>
	/// Gets or sets the hashed password.
	/// </summary>
	public string? Hash { get; set; }
}
