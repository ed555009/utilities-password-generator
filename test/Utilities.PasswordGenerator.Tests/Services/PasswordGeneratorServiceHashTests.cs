using System.Security.Cryptography;
using System.Text;
using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Models.Responses;
using Utilities.PasswordGenerator.Services;

namespace Utilities.PasswordGenerator.Tests.Services;

/// <summary>
/// Pins the PBKDF2 parameters and the verification rules of <see cref="PasswordGeneratorService"/>.
/// A change to these values changes the strength of stored hashes, or lets an attacker request an expensive computation.
/// </summary>
public sealed class PasswordGeneratorServiceHashTests
{
	private const string Password = "Pässwörd-中文-!@#";
	private const int CurrentIterations = 210_000;
	private const int CurrentSaltSize = 16;
	private const int CurrentHashSize = 64;
	private const int LegacyHashSize = 128;

	// Compute 1 hash for all tests. Each Hash call runs 210,000 iterations.
	private static readonly HashedPasswordModel _current = new PasswordGeneratorService().Hash(Password);

	private readonly PasswordGeneratorService _service = new();

	[Fact]
	public void Hash_AnyPassword_ReturnsCurrentParameters()
	{
		// Then
		Assert.Equal(CurrentIterations, _current.Iterations);
		Assert.Equal(CurrentSaltSize * 2, _current.Salt.Length);
		Assert.Equal(CurrentHashSize * 2, _current.Hash.Length);
	}

	[Fact]
	public void Hash_AnyPassword_ReturnsSameHashAsPbkdf2()
	{
		// When
		// Compute the reference with the one-shot .NET API.
		var expected = Rfc2898DeriveBytes.Pbkdf2(
			Encoding.UTF8.GetBytes(Password),
			Convert.FromHexString(_current.Salt),
			CurrentIterations,
			HashAlgorithmName.SHA512,
			CurrentHashSize);

		// Then
		Assert.Equal(Convert.ToHexString(expected), _current.Hash);
	}

	[Fact]
	public void Hash_SamePasswordTwice_ReturnsDifferentSalts()
	{
		// When
		var other = _service.Hash(Password);

		// Then
		Assert.NotEqual(_current.Salt, other.Salt);
		Assert.NotEqual(_current.Hash, other.Hash);
	}

	[Fact]
	public void Verify_CurrentHash_ReturnsTrue()
	{
		// When
		var result = _service.Verify(CreateCurrentModel(Password));

		// Then
		Assert.True(result);
	}

	[Fact]
	public void Verify_CurrentHashWrongPassword_ReturnsFalse()
	{
		// When
		var result = _service.Verify(CreateCurrentModel(Password + "x"));

		// Then
		Assert.False(result);
	}

	[Fact]
	public void Verify_ChangedHash_ReturnsFalse()
	{
		// Given
		var data = CreateCurrentModel(Password);
		var lastChar = data.Hash![^1] == '0' ? '1' : '0';
		data.Hash = data.Hash[..^1] + lastChar;

		// When
		var result = _service.Verify(data);

		// Then
		Assert.False(result);
	}

	[Fact]
	public void Verify_HigherIterations_ReturnsTrue()
	{
		// Given
		// A future version can increase the iteration count. This version must verify such a hash.
		const int iterations = 250_000;
		var salt = RandomNumberGenerator.GetBytes(CurrentSaltSize);
		var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(Password), salt, iterations, HashAlgorithmName.SHA512, CurrentHashSize);
		var data = new VerifyPasswordModel
		{
			Password = Password,
			Salt = Convert.ToHexString(salt),
			Hash = Convert.ToHexString(hash),
			Iterations = iterations
		};

		// When
		var result = _service.Verify(data);

		// Then
		Assert.True(result);
	}

	[Theory]
	[InlineData(-1)]
	[InlineData(0)]
	[InlineData(12_800)]
	[InlineData(209_999)]
	[InlineData(1_000_001)]
	[InlineData(int.MaxValue)]
	public void Verify_IterationsOutOfRange_ThrowsArgumentOutOfRangeException(int iterations)
	{
		// Given
		var data = CreateCurrentModel(Password);
		data.Iterations = iterations;

		// When
		void Act() => _service.Verify(data);

		// Then
		var ex = Assert.Throws<ArgumentOutOfRangeException>(Act);
		Assert.Equal(nameof(VerifyPasswordModel.Iterations), ex.ParamName);
	}

	[Fact]
	public void Verify_NullIterationsWithCurrentHashLength_ThrowsArgumentException()
	{
		// Given
		// A null iteration count selects the 6.0.x parameters. These parameters need a 128-byte hash.
		var data = CreateCurrentModel(Password);
		data.Iterations = null;

		// When
		void Act() => _service.Verify(data);

		// Then
		_ = Assert.Throws<ArgumentException>(Act);
	}

	[Fact]
	public void Verify_CurrentIterationsWithLegacyHashLength_ThrowsArgumentException()
	{
		// Given
		var data = CreateCurrentModel(Password);
		data.Hash = new string('A', LegacyHashSize * 2);

		// When
		void Act() => _service.Verify(data);

		// Then
		_ = Assert.Throws<ArgumentException>(Act);
	}

	[Fact]
	public void Verify_MalformedHash_ThrowsFormatException()
	{
		// Given
		var data = CreateCurrentModel(Password);
		data.Hash = "XYZ";

		// When
		void Act() => _service.Verify(data);

		// Then
		_ = Assert.Throws<FormatException>(Act);
	}

	[Fact]
	public void Verify_NullData_ThrowsArgumentNullException()
	{
		// When
		void Act() => _service.Verify(null!);

		// Then
		var ex = Assert.Throws<ArgumentNullException>(Act);
		Assert.Equal("data", ex.ParamName);
	}

	[Theory]
	[InlineData(null, true)]
	[InlineData(12_800, true)]
	[InlineData(209_999, true)]
	[InlineData(210_000, false)]
	[InlineData(250_000, false)]
	public void NeedsRehash_StoredIterations_ReturnsExpectedResult(int? iterations, bool expected)
	{
		// Given
		var data = CreateCurrentModel(Password);
		data.Iterations = iterations;

		// When
		var result = _service.NeedsRehash(data);

		// Then
		Assert.Equal(expected, result);
	}

	[Fact]
	public void NeedsRehash_NullData_ThrowsArgumentNullException()
	{
		// When
		void Act() => _service.NeedsRehash(null!);

		// Then
		_ = Assert.Throws<ArgumentNullException>(Act);
	}

	/// <summary>
	/// Creates a verify model from the shared current hash.
	/// </summary>
	/// <param name="password">The password to verify.</param>
	/// <returns>A new model. Each test can change the model.</returns>
	private static VerifyPasswordModel CreateCurrentModel(string password) =>
		new()
		{
			Password = password,
			Salt = _current.Salt,
			Hash = _current.Hash,
			Iterations = _current.Iterations
		};
}
