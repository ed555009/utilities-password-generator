namespace Utilities.PasswordGenerator.Internal;

/// <summary>
/// Converts byte arrays to uppercase hex strings and back.
/// </summary>
/// <remarks>
/// netstandard2.1 does not contain Convert.ToHexString and Convert.FromHexString.
/// The output and the exceptions are the same as these methods.
/// </remarks>
internal static class HexConverter
{
	/// <summary>
	/// Converts the bytes to an uppercase hex string.
	/// </summary>
	/// <param name="bytes">The bytes to convert.</param>
	/// <returns>The uppercase hex string. The length is 2 times the byte count.</returns>
	public static string ToHexString(byte[] bytes) =>
		BitConverter.ToString(bytes).Replace("-", string.Empty);

	/// <summary>
	/// Converts a hex string to bytes.
	/// </summary>
	/// <param name="hex">The hex string. Uppercase and lowercase characters are valid.</param>
	/// <returns>The bytes.</returns>
	/// <exception cref="FormatException">The length is odd, or the string contains a character that is not hex.</exception>
	public static byte[] FromHexString(string hex)
	{
		if (hex.Length % 2 != 0)
			throw new FormatException("The hex string length must be even.");

		var bytes = new byte[hex.Length / 2];

		for (var i = 0; i < bytes.Length; i++)
			bytes[i] = (byte)((ParseNibble(hex[i * 2]) << 4) | ParseNibble(hex[(i * 2) + 1]));

		return bytes;
	}

	/// <summary>
	/// Converts 1 hex character to its value.
	/// </summary>
	/// <param name="c">The hex character.</param>
	/// <returns>The value from 0 to 15.</returns>
	/// <exception cref="FormatException">The character is not hex.</exception>
	private static int ParseNibble(char c) =>
		c switch
		{
			>= '0' and <= '9' => c - '0',
			>= 'A' and <= 'F' => c - 'A' + 10,
			>= 'a' and <= 'f' => c - 'a' + 10,
			_ => throw new FormatException("The string contains a character that is not hex.")
		};
}
