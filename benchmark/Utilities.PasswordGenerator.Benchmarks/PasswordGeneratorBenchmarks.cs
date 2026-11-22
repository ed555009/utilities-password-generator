using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Services;

namespace Utilities.PasswordGenerator.Benchmarks;

/// <summary>
/// Measures password generation, hashing and verification.
/// </summary>
/// <remarks>
/// The "LegacyHash" benchmark verifies a hash with the 6.0.x parameters. The time must stay equal to version 6.0.910.
/// NOTE: BenchmarkDotNet does not accept a sealed benchmark class.
/// </remarks>
[MemoryDiagnoser]
public class PasswordGeneratorBenchmarks
{
	// The password is not a secret. Do not print generated passwords in the benchmark.
	private const string Password = "Benchmark-Password-1";

	private readonly PasswordGeneratorService _service = new();
	private VerifyPasswordModel _currentHash = null!;
	private VerifyPasswordModel _legacyHash = null!;

	/// <summary>
	/// Computes the hashes that the verification benchmarks use.
	/// </summary>
	[GlobalSetup]
	public void Setup()
	{
		var current = _service.Hash(Password);
		_currentHash = new VerifyPasswordModel
		{
			Password = Password,
			Hash = current.Hash,
			Salt = current.Salt,
			Iterations = current.Iterations
		};
		_legacyHash = CreateLegacyHash(Password);

		// Stop the run when a setup hash is not valid. A failed Verify returns early and gives a wrong time.
		if (!_service.Verify(_currentHash) || !_service.Verify(_legacyHash))
			throw new InvalidOperationException("The benchmark hash is not valid.");
	}

	/// <summary>
	/// Generates a password with the default arguments.
	/// </summary>
	[Benchmark]
	public string Generate_Length8() =>
		_service.Generate();

	/// <summary>
	/// Generates a password with the maximum length.
	/// </summary>
	[Benchmark]
	public string Generate_Length32() =>
		_service.Generate(32);

	/// <summary>
	/// Hashes a password with the 10.0 parameters.
	/// </summary>
	[Benchmark]
	public string Hash() =>
		_service.Hash(Password).Hash;

	/// <summary>
	/// Verifies a hash with the 10.0 parameters.
	/// </summary>
	[Benchmark]
	public bool Verify_CurrentHash() =>
		_service.Verify(_currentHash);

	/// <summary>
	/// Verifies a hash with the 6.0.x parameters.
	/// </summary>
	[Benchmark]
	public bool Verify_LegacyHash() =>
		_service.Verify(_legacyHash);

	/// <summary>
	/// Creates a hash with the 6.0.x parameters: a 128-byte salt, 12,800 iterations and a 128-byte hash.
	/// </summary>
	/// <param name="password">The password to hash.</param>
	/// <returns>A verify model without an iteration count.</returns>
	private static VerifyPasswordModel CreateLegacyHash(string password)
	{
		var salt = RandomNumberGenerator.GetBytes(128);
		var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 12_800, HashAlgorithmName.SHA512, 128);

		return new VerifyPasswordModel
		{
			Password = password,
			Hash = Convert.ToHexString(hash),
			Salt = Convert.ToHexString(salt),
			Iterations = null
		};
	}
}
