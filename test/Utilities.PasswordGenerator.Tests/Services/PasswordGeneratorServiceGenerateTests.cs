using Utilities.PasswordGenerator.Services;

namespace Utilities.PasswordGenerator.Tests.Services;

/// <summary>
/// Pins the argument validation and the shuffle of <see cref="PasswordGeneratorService.Generate"/>.
/// Invalid arguments gave passwords longer than the requested length or with ambiguous characters.
/// </summary>
public sealed class PasswordGeneratorServiceGenerateTests
{
	private readonly PasswordGeneratorService _service = new();

	[Theory]
	[InlineData(-1, 1, 1, 1, "requiredUppercase")]
	[InlineData(1, -1, 1, 1, "requiredLowercase")]
	[InlineData(1, 1, -1, 1, "requiredNumeric")]
	[InlineData(1, 1, 1, -1, "requiredSpecialChar")]
	[InlineData(-2, 1, 1, 1, "requiredUppercase")]
	public void Generate_NegativeCount_ThrowsArgumentOutOfRangeException(int upper, int lower, int numeric, int special, string paramName)
	{
		// When
		void Act() => _service.Generate(8, upper, lower, numeric, special);

		// Then
		var ex = Assert.Throws<ArgumentOutOfRangeException>(Act);
		Assert.Equal(paramName, ex.ParamName);
	}

	[Theory]
	[InlineData("0O1Il")]
	[InlineData("!a")]
	[InlineData("!5")]
	[InlineData("! ")]
	[InlineData("!\t")]
	[InlineData("!\n")]
	[InlineData("!\u0001")]
	[InlineData("!\U0001F600")]
	public void Generate_SpecialCharsNotAllowed_ThrowsArgumentException(string specialChars)
	{
		// When
		void Act() => _service.Generate(16, specialChars: specialChars);

		// Then
		var ex = Assert.Throws<ArgumentException>(Act);
		Assert.Equal("specialChars", ex.ParamName);
	}

	[Fact]
	public void Generate_DuplicateSpecialChars_UsesOnlyGivenSpecialChars()
	{
		// When
		var result = _service.Generate(32, 0, 0, 0, 8, "!!!!!!!#");

		// Then
		Assert.Equal(32, result.Length);
		Assert.All(result.Where(c => !char.IsLetterOrDigit(c)), c => Assert.Contains(c, "!#"));
		Assert.True(result.Count(c => !char.IsLetterOrDigit(c)) >= 8);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	public void Generate_NoSpecialChars_ReturnsOnlyLettersAndDigits(string? specialChars)
	{
		// When
		var result = _service.Generate(32, specialChars: specialChars);

		// Then
		Assert.Equal(32, result.Length);
		Assert.All(result, c => Assert.True(char.IsLetterOrDigit(c)));
	}

	[Fact]
	public void Generate_ValidArguments_ReturnsRequestedLength()
	{
		for (var length = 8; length <= 32; length++)
		{
			// When
			var result = _service.Generate(length, 2, 2, 2, 2);

			// Then
			Assert.Equal(length, result.Length);
		}
	}

	[Fact]
	public void Generate_OneUppercase_PlacesUppercaseAtEachPositionWithSameProbability()
	{
		// Given
		// The password has 1 uppercase and 7 lowercase characters. The shuffle selects the uppercase position.
		const int runs = 4_000;
		var counts = new int[8];

		// When
		for (var i = 0; i < runs; i++)
		{
			var result = _service.Generate(8, 1, 7, 0, 0);
			counts[result.IndexOf(result.First(char.IsUpper))]++;
		}

		// Then
		// The expected count is 500. The range 350 to 650 is about 7 standard deviations.
		Assert.All(counts, count => Assert.InRange(count, 350, 650));
	}
}
