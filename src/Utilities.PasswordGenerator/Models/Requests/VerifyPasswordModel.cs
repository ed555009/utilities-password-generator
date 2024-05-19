using Utilities.PasswordGenerator.Models.Responses;

namespace Utilities.PasswordGenerator.Models.Requests;

/// <summary>
/// Represents a model used to verify a password.
/// </summary>
public class VerifyPasswordModel : HashedPasswordModel
{
	/// <summary>
	/// Gets or sets the password to be verified.
	/// </summary>
	public string? Password { get; set; }
}
