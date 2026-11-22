using Utilities.PasswordGenerator.Internal;

namespace Utilities.PasswordGenerator.Tests.Internal;

/// <summary>
/// Pins the behavior of <see cref="HexConverter"/> to Convert.ToHexString and Convert.FromHexString.
/// Stored hashes and salts use this format. A different result makes stored hashes fail verification.
/// </summary>
public sealed class HexConverterTests
{
	[Theory]
	[InlineData(new byte[0])]
	[InlineData(new byte[] { 0x00 })]
	[InlineData(new byte[] { 0x01, 0xAB, 0xCD, 0xEF, 0xFF })]
	public void ToHexString_AnyBytes_ReturnsSameAsConvert(byte[] bytes)
	{
		// When
		var result = HexConverter.ToHexString(bytes);

		// Then
		Assert.Equal(Convert.ToHexString(bytes), result);
	}

	[Theory]
	[InlineData("")]
	[InlineData("00")]
	[InlineData("01ABCDEFFF")]
	[InlineData("01abcdefff")]
	[InlineData("01AbCdEfFf")]
	public void FromHexString_ValidHex_ReturnsSameAsConvert(string hex)
	{
		// When
		var result = HexConverter.FromHexString(hex);

		// Then
		Assert.Equal(Convert.FromHexString(hex), result);
	}

	[Theory]
	[InlineData("A")]
	[InlineData("ABC")]
	[InlineData("0G")]
	[InlineData("ZZ")]
	[InlineData("0 ")]
	[InlineData("-1")]
	public void FromHexString_InvalidHex_ThrowsFormatException(string hex)
	{
		// When
		void Act() => HexConverter.FromHexString(hex);

		// Then
		_ = Assert.Throws<FormatException>(Act);
		_ = Assert.Throws<FormatException>(() => Convert.FromHexString(hex));
	}
}
