using Utilities.PasswordGenerator.Models.Requests;
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
	[InlineData(8)]
	[InlineData(16)]
	[InlineData(32)]
	public void GenerateHashed_ShouldSuccess(int length)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var result = service.GenerateHashed(length);

		_outputHelper.WriteLine(result.Hash);

		// Then
		Assert.Equal(256, result.Hash?.Length);
		Assert.Equal(256, result.Salt?.Length);
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

		_outputHelper.WriteLine(result);

		// Then
		Assert.Equal(8, result.Length);
	}

	[Theory]
	[InlineData("!@#$%^*()-_=+?")]
	[InlineData(null)]
	public void GenerateHashed_WithCustomSpecialChars_ShouldSuccess(string? specialChars)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var result = service.GenerateHashed(8, 1, 1, 1, 1, specialChars);

		_outputHelper.WriteLine(result.Hash);

		// Then
		Assert.Equal(256, result.Hash?.Length);
		Assert.Equal(256, result.Salt?.Length);
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

	[Theory]
	[InlineData(7)]
	[InlineData(33)]
	public void GenerateHashed_WithLengthOutOfRange_ShouldThrow(int length)
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => service.GenerateHashed(length));

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

	[Fact]
	public void GenerateHashed_WithLengthLessThanRequired_ShouldThrow()
	{
		// Given
		var service = new PasswordGeneratorService();

		// When
		var ex = Assert.Throws<ArgumentException>(() => service.GenerateHashed(8, 3, 3, 3, 3));

		// Then
		Assert.NotNull(ex);
	}

	[Fact]
	public void Verify_ShouldSuccess()
	{
		// Given
		var service = new PasswordGeneratorService();
		var password = "abcd1234";
		var hashed = service.Hash(password);

		// When
		var result = service.Verify(new VerifyPasswordModel
		{
			Password = password,
			Salt = hashed.Salt,
			Hash = hashed.Hash
		});

		// Then
		Assert.True(result);
	}

	[Theory]
	[InlineData(null, null, null)]
	[InlineData("password", null, null)]
	[InlineData("password", "salt", null)]
	public void Verify_WithNullData_ShouldThrow(string? password, string? salt, string? hash)
	{
		// Given
		var service = new PasswordGeneratorService();
		var data = new VerifyPasswordModel
		{
			Password = password,
			Salt = salt,
			Hash = hash
		};

		// When
		var ex = Assert.Throws<ArgumentNullException>(() => service.Verify(data));

		// Then
		Assert.NotNull(ex);
	}
}
