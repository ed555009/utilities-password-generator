# Utilities.PasswordGenerator

[![GitHub](https://img.shields.io/github/license/ed555009/utilities-password-generator)](LICENSE)
[![Build Status](https://github.com/ed555009/utilities-password-generator/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/ed555009/utilities-password-generator/actions/workflows/build.yml)
[![Nuget](https://img.shields.io/nuget/v/Utilities.PasswordGenerator)](https://www.nuget.org/packages/Utilities.PasswordGenerator)

![Coverage](https://sonarcloud.io/api/project_badges/measure?project=utilities-password-generator&metric=coverage)
![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=utilities-password-generator&metric=alert_status)
![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-password-generator&metric=reliability_rating)
![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-password-generator&metric=security_rating)
![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=utilities-password-generator&metric=vulnerabilities)

Ambiguous avoid, generated password will not contain `0` `O` `1` `I` `l`

## Installation

```bash
dotnet add package Utilities.PasswordGenerator
```

## Using service

### Simple usage

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 8 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and 1 special character
		return passwordGeneratorService.Generate();
	}
}
```

### Generate with specific length

You can generate 8~32 characters password by specifying the length. (default: 8)

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 16 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and 1 special character
		return passwordGeneratorService.Generate(16);
	}
}
```

### Generate with required characters options

You can generate 8~32 characters password with specific options, i.e. at least 3 uppercase, 3 lowercase, 2 numeric and 1 special character.

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 16 characters password with at least 3 uppercase, 3 lowercase, 2 numeric and 1 special character
		return passwordGeneratorService.Generate(16, 3, 3, 2, 1);
	}
}
```

### Custom special characters

Default special characters are `!` `@` `#` `$` `%` `^` `*` `(` `)` `-` `_` `=` `+` `?`. You can setup your own special characters by giving `specialChars` parameter.

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 16 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and 1 special character (~!@#<>)
		return passwordGeneratorService.Generate(16, specialChars: "~!@#<>");
	}
}
```

In case you don't want any special characters, you can set `specialChars` to empty string or null.

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 16 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and no special character
		return passwordGeneratorService.Generate(16, specialChars: null);
	}
}
```

## Password hashing

Password hashing function uses the `PBKDF2` (Password-Based Key Derivation Function 2) algorithm to generate secure password hash, includes two key parameters:

- `_keySize: 128`
Generates a random salt value byte array using the RandomNumberGenerator.GetBytes method. With _keySize set to 128, this means the generated salt value will have 128 bytes (256 characters).

- `_iterations: 12_800`

These parameters control the output size of the hash calculation and the computational strength, thereby enhancing the security of passwords. This provides a robust password hashing solution suitable for applications requiring high security.

Hashed password will return in `HashedPasswordModel` object which contains `Hash` and `Salt`, you should store both values for later password verification.

### Generate password hash

```csharp
using Utilities.PasswordGenerator.Models.Responses;
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public HashedPasswordModel GenerateHashed()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate hash of 16 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and 1 special character
		return passwordGeneratorService.GenerateHashed(16);
	}
}
```

### Verify password

```csharp
using Utilities.PasswordGenerator.Models.Requests;
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public bool Verify()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// prepare password, hash and salt
		var data = new VerifyPasswordModel
		{
			Password = "PLAINTEXT_PASSWORD",
			Hash = "HASH",
			Salt = "SALT"
		};

		// verify password with hash and salt
		return passwordGeneratorService.Verify(data);
	}
}
```

## Use dependency injection

### Register services

```csharp
using Utilities.PasswordGenerator.Interfaces;
using Utilities.PasswordGenerator.Services;

ConfigureServices(IServiceCollection services)
{
	// this injects as SINGLETON
	services.AddSingleton<IPasswordGeneratorService, PasswordGeneratorService>();
}
```

### Using service

```csharp
using Utilities.PasswordGenerator.Interfaces;

public class MyProcess
{
	private readonly IPasswordGeneratorService _passwordGeneratorService;

	public MyProcess(IPasswordGeneratorService passwordGeneratorService) =>
		_passwordGeneratorService = _passwordGeneratorService;

	public string Generate() =>
		_passwordGeneratorService.Generate();
}
```

## Benchmark

The benchmark project is in `benchmark/Utilities.PasswordGenerator.Benchmarks`. Run it with this command:

```bash
cd benchmark/Utilities.PasswordGenerator.Benchmarks
dotnet run -c Release -f net10.0 -- --filter '*' --runtimes net8.0 net10.0
```

The benchmark has 2 verification scenarios:

- `CurrentHash`: a hash with the 10.0 parameters.
- `LegacyHash`: a hash with the 6.0.x parameters. Consumers verify stored 6.0.x hashes with this path.

The 2 runtimes use different assemblies of the package:

- .NET 10.0 loads the `net10.0` assembly. PBKDF2 uses the one-shot `Rfc2898DeriveBytes.Pbkdf2`.
- .NET 8.0 loads the `netstandard2.1` assembly. PBKDF2 uses the `Rfc2898DeriveBytes` constructor. .NET 9.0 uses the same assembly.

### Version 10.0

```
BenchmarkDotNet v0.15.8, macOS 27.0.1 (26A434) [Darwin 27.0.0]
Apple M3 Pro, 1 CPU, 11 logical and 11 physical cores
.NET SDK 11.0.100
  [Host]    : .NET 10.0.15 (10.0.15, 10.0.1526.53008), Arm64 RyuJIT armv8.0-a
  .NET 10.0 : .NET 10.0.15 (10.0.15, 10.0.1526.53008), Arm64 RyuJIT armv8.0-a
  .NET 8.0  : .NET 8.0.6 (8.0.6, 8.0.624.26715), Arm64 RyuJIT armv8.0-a
```

| Method             | Runtime   | Mean         | Error        | StdDev       | Allocated |
|------------------- |---------- |-------------:|-------------:|-------------:|----------:|
| Generate_Length8   | .NET 10.0 |     1.595 μs |     0.032 μs |     0.057 μs |    1264 B |
| Generate_Length8   | .NET 8.0  |     1.616 μs |     0.031 μs |     0.026 μs |    1296 B |
| Generate_Length32  | .NET 10.0 |     6.838 μs |     0.135 μs |     0.171 μs |    1512 B |
| Generate_Length32  | .NET 8.0  |     6.760 μs |     0.112 μs |     0.094 μs |    1544 B |
| Hash               | .NET 10.0 |    69.486 ms |     1.186 ms |     1.109 ms |    1072 B |
| Hash               | .NET 8.0  |   207.648 ms |     4.135 ms |     8.448 ms |    1661 B |
| Verify_CurrentHash | .NET 10.0 |    71.024 ms |     1.027 ms |     0.910 ms |     264 B |
| Verify_CurrentHash | .NET 8.0  |   204.369 ms |     3.799 ms |     8.496 ms |     813 B |
| Verify_LegacyHash  | .NET 10.0 |     8.704 ms |     0.171 ms |     0.245 ms |     504 B |
| Verify_LegacyHash  | .NET 8.0  |    24.763 ms |     0.491 ms |     0.765 ms |    1102 B |

### Comparison with version 6.0.910

The same machine ran version 6.0.910 with the same benchmark scenarios on the same day. Version 6.0.910 has no `CurrentHash` scenario. The table compares its `Verify` with both 10.0 scenarios.

| Operation | Runtime | 6.0.910 | 10.0 | Time | Memory |
|---|---|---|---|---:|---:|
| `Generate()` | .NET 10.0 | 1.504 μs / 1,264 B | 1.595 μs / 1,264 B | +6.1% | 0% |
| `Generate()` | .NET 8.0 | 1.497 μs / 1,296 B | 1.616 μs / 1,296 B | +7.9% | 0% |
| `Generate(32)` | .NET 10.0 | 6.013 μs / 3,320 B | 6.838 μs / 1,512 B | +13.7% | -54.5% |
| `Generate(32)` | .NET 8.0 | 6.127 μs / 3,416 B | 6.760 μs / 1,544 B | +10.3% | -54.8% |
| `Hash` | .NET 10.0 | 8.512 ms / 1,456 B | 69.486 ms / 1,072 B | ×8.2 | -26.4% |
| `Hash` | .NET 8.0 | 8.820 ms / 1,456 B | 207.648 ms / 1,661 B | ×23.5 | +14.1% |
| `Verify`, 10.0 hash | .NET 10.0 | 8.584 ms / 456 B | 71.024 ms / 264 B | ×8.3 | -42.1% |
| `Verify`, 10.0 hash | .NET 8.0 | 8.729 ms / 456 B | 204.369 ms / 813 B | ×23.4 | +78.3% |
| `Verify`, 6.0.x hash | .NET 10.0 | 8.584 ms / 456 B | 8.704 ms / 504 B | +1.4% | +10.5% |
| `Verify`, 6.0.x hash | .NET 8.0 | 8.729 ms / 456 B | 24.763 ms / 1,102 B | ×2.8 | +141.7% |

- On .NET 10, `Hash` and `Verify` with the 10.0 parameters take 8.2 times the 6.0.910 time. Version 6.0.910 computed 2 blocks of 12,800 iterations. Version 10.0 computes 1 block of 210,000 iterations. The time increase is the cost of the stronger hash.
- On .NET 8 and .NET 9, `Hash` and `Verify` take about 3 times the .NET 10 time. `netstandard2.1` has no one-shot `Rfc2898DeriveBytes.Pbkdf2`. Use .NET 10 for login services.
- On .NET 10, `Verify` for a stored 6.0.x hash takes the same time as version 6.0.910 (+1.4%).
- `Generate(32)` allocates 54% less memory. The argument checks and the Fisher-Yates shuffle add 0.1 μs to 0.8 μs for each call.
- Plan the login capacity with the `Verify_CurrentHash` time. One CPU core verifies about 14 passwords per second on .NET 10.
- NOTE: The published package 6.0.910 is a Debug build. The `Generate` results of 6.0.910 include this effect. The `Hash` and `Verify` results do not, because the platform crypto library runs the PBKDF2 loop.
