namespace Utilities.PasswordGenerator.Models
{
	/// <summary>
	/// Represents a base class for salt models.
	/// </summary>
	public abstract class SaltModel
	{
		/// <summary>
		/// Gets or sets the salt used for hashing the password.
		/// </summary>
		public string? Salt { get; set; }
	}
}
