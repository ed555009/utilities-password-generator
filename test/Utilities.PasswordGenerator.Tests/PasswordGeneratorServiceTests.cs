using Utilities.PasswordGenerator.Services;
using Xunit.Abstractions;

namespace Utilities.PasswordGenerator.Tests;

public class PasswordGeneratorServiceTests
{
	private readonly ITestOutputHelper _outputHelper;

	public PasswordGeneratorServiceTests(ITestOutputHelper outputHelper) =>
		_outputHelper = outputHelper;

	[Theory]
	[InlineData(8)]
	[InlineData(16)]
	[InlineData(32)]
	public void Generate_ShouldSuccess(int length)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var result = service.Generate(length);

		_outputHelper.WriteLine(result);

		// Then
		Assert.Equal(length, result.Length);
	}

	[Theory]
	[InlineData("!@#$%^*()-_=+?")]
	[InlineData(null)]
	public void Generate_WithCustomSpecialChars_ShouldSuccess(string? specialChars)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var result = service.Generate(8, 1, 1, 1, 1, specialChars);

		// Then
		Assert.Equal(8, result.Length);
	}

	[Theory]
	[InlineData(7)]
	[InlineData(33)]
	public void Generate_WithLengthOutOfRange_ShouldThrow(int length)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => service.Generate(length));

		// Then
		Assert.NotNull(ex);
	}

	[Fact]
	public void Generate_WithLengthLessThanRequired_ShouldThrow()
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var ex = Assert.Throws<ArgumentException>(() => service.Generate(8, 3, 3, 3, 3));

		// Then
		Assert.NotNull(ex);
	}
}
