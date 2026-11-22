using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Services;

namespace Utilities.PasswordGenerator.Tests.Services;

/// <summary>
/// Pins the password policy of <see cref="PasswordGeneratorService.Generate"/> and the basic hash round trip.
/// A change to the policy changes the passwords that users see and type.
/// </summary>
public sealed class PasswordGeneratorServiceTests
{
	private const string Uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
	private const string Lowercase = "abcdefghijkmnopqrstuvwxyz";
	private const string Digits = "23456789";
	private const string Ambiguous = "0O1Il";

	private readonly PasswordGeneratorService _service = new();

	[Theory]
	[InlineData(8)]
	[InlineData(16)]
	[InlineData(32)]
	public void Generate_ValidLength_ReturnsPasswordOfThatLength(int length)
	{
		// When
		var result = _service.Generate(length);

		// Then
		Assert.Equal(length, result.Length);
	}

	[Theory]
	[InlineData(PasswordGeneratorService.DefaultSpecialChars)]
	[InlineData(null)]
	public void Generate_CustomSpecialChars_ReturnsPasswordOfThatLength(string? specialChars)
	{
		// When
		var result = _service.Generate(8, 1, 1, 1, 1, specialChars);

		// Then
		Assert.Equal(8, result.Length);
	}

	[Theory]
	[InlineData(7)]
	[InlineData(33)]
	public void Generate_LengthOutOfRange_ThrowsArgumentOutOfRangeException(int length)
	{
		// When
		void Act() => _service.Generate(length);

		// Then
		var ex = Assert.Throws<ArgumentOutOfRangeException>(Act);
		Assert.Equal("length", ex.ParamName);
	}

	[Fact]
	public void Generate_LengthLessThanRequired_ThrowsArgumentException()
	{
		// When
		void Act() => _service.Generate(8, 3, 3, 3, 3);

		// Then
		_ = Assert.Throws<ArgumentException>(Act);
	}

	[Theory]
	[InlineData(8, 1, 1, 1, 1)]
	[InlineData(16, 3, 3, 2, 1)]
	[InlineData(32, 8, 8, 8, 8)]
	[InlineData(12, 0, 6, 0, 6)]
	public void Generate_RequiredCounts_ContainsAtLeastRequiredOfEachCategory(int length, int upper, int lower, int digits, int special)
	{
		for (var i = 0; i < 100; i++)
		{
			// When
			var result = _service.Generate(length, upper, lower, digits, special);

			// Then
			Assert.True(result.Count(c => Uppercase.Contains(c)) >= upper);
			Assert.True(result.Count(c => Lowercase.Contains(c)) >= lower);
			Assert.True(result.Count(c => Digits.Contains(c)) >= digits);
			Assert.True(result.Count(c => PasswordGeneratorService.DefaultSpecialChars.Contains(c)) >= special);
		}
	}

	[Fact]
	public void Generate_AnyArguments_ExcludesAmbiguousCharacters()
	{
		for (var i = 0; i < 1_000; i++)
		{
			// When
			var result = _service.Generate(32);

			// Then
			Assert.DoesNotContain(result, c => Ambiguous.Contains(c));
		}
	}

	[Fact]
	public void Generate_CustomSpecialChars_UsesOnlyAllowedCharacters()
	{
		// Given
		const string specialChars = "~<>";
		const string allowed = Uppercase + Lowercase + Digits + specialChars;

		for (var i = 0; i < 100; i++)
		{
			// When
			var result = _service.Generate(32, specialChars: specialChars);

			// Then
			Assert.All(result, c => Assert.Contains(c, allowed));
		}
	}

	[Fact]
	public void Verify_CorrectPassword_ReturnsTrue()
	{
		// Given
		const string password = "abcd1234";
		var hashed = _service.Hash(password);

		// When
		var result = _service.Verify(new VerifyPasswordModel
		{
			Password = password,
			Salt = hashed.Salt,
			Hash = hashed.Hash,
			Iterations = hashed.Iterations
		});

		// Then
		Assert.True(result);
	}

	[Theory]
	[InlineData(null, null, null, "data.Password")]
	[InlineData("password", null, null, "data.Salt")]
	[InlineData("password", "salt", null, "data.Hash")]
	public void Verify_NullField_ThrowsArgumentNullException(string? password, string? salt, string? hash, string property)
	{
		// Given
		var data = new VerifyPasswordModel
		{
			Password = password,
			Salt = salt,
			Hash = hash
		};

		// When
		void Act() => _service.Verify(data);

		// Then
		var ex = Assert.Throws<ArgumentNullException>(Act);
		// ParamName is the method parameter. The message names the property.
		Assert.Equal("data", ex.ParamName);
		Assert.Contains(property, ex.Message);
	}
}
