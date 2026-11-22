using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Services;

namespace Utilities.PasswordGenerator.Tests.Services;

/// <summary>
/// Pins the hash compatibility of <see cref="PasswordGeneratorService"/> with version 6.0.x.
/// Consumers store 6.0.x hashes. A change to the PBKDF2 code must not make these hashes fail verification.
/// </summary>
public sealed class PasswordGeneratorServiceCompatibilityTests
{
	private readonly PasswordGeneratorService _service = new();

	/// <summary>
	/// Gets hashes that package 6.0.910 computed on .NET 6.0.31: password, salt and hash.
	/// </summary>
	public static TheoryData<string, string, string> Version6Hashes => new()
	{
		{
			"abcd1234",
			"4003E8794A73F843DD7CCE23FF2AF8062758C1C2C1C2A2E0BBFA6879A2FB6B03141DE489494BDD37B60794E558D359FC931D046256DAC8C1118F00985BBDC2138B1A5A506DCB6DA67FD51BD601F8C26B4B286620139B96F427036C033DED67F9DCA9698097847EA05012187458F7D044C3A5A39AFEFC5CB2136BD9369905C6A2",
			"C1DCBE17D2FE3EE48BA1B04E8A927311FC453A17142BEFA860B4B373F244D7102F17C8D7EB6A6CEBD9E89CF498F09E5573EC2121468D0CB3E6748CEB3354362A3CE794AAE8AE37C14D91BB3F4DCEB5CC620230CFECD1F6612CA00CEBE1CEDBB4A8EF244F0F858CB32D36E790AC339ACB077AF1FF9966AB51051EFF78F077FB12"
		},
		{
			"Pässwörd-中文-!@#",
			"C90CA30197B60E523B7F83427B4FCE8EDF359532E47F7956A423A1A8B19B3A092AEEF3848701CCAA4ABFE7EBADEED6F27CA854905518055B62413DF270876CC9A412F2DE551157CB33E04262E17E18C2B1937D4E230E43369BBF5D85A4DD3590D2114202739826AEB891A205306B044C6B93360BD3F3EADEA3AE0FA658950F2A",
			"53D2078F779B2714666A52B1FE39CA13C717B1DF9F21703DAC75066CFA00C1A3C2B0961F949FD22F9A981676A31AC4F3D679C764861F47CFB4A208DD29F45C3BF2AE33331D254F250C141C8BA3CEEC31A901BFB13A2E1C59EEF56B3EF9C4EE65C77C530A32CD0D60C755785A66DBAA6B16E6703F1814A63FEED8FE359A1BE12C"
		},
	};

	[Theory]
	[MemberData(nameof(Version6Hashes))]
	public void Verify_HashFromVersion6_ReturnsTrue(string password, string salt, string hash)
	{
		// Given
		var data = new VerifyPasswordModel { Password = password, Salt = salt, Hash = hash };

		// When
		var result = _service.Verify(data);

		// Then
		Assert.True(result);
	}

	[Theory]
	[MemberData(nameof(Version6Hashes))]
	public void Verify_WrongPasswordForHashFromVersion6_ReturnsFalse(string password, string salt, string hash)
	{
		// Given
		var data = new VerifyPasswordModel { Password = password + "x", Salt = salt, Hash = hash };

		// When
		var result = _service.Verify(data);

		// Then
		Assert.False(result);
	}

	[Theory]
	[MemberData(nameof(Version6Hashes))]
	public void Verify_LowercaseHexFromVersion6_ReturnsTrue(string password, string salt, string hash)
	{
		// Given
		var data = new VerifyPasswordModel
		{
			Password = password,
			Salt = salt.ToLowerInvariant(),
			Hash = hash.ToLowerInvariant()
		};

		// When
		var result = _service.Verify(data);

		// Then
		Assert.True(result);
	}
}
