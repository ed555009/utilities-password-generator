# Utilities.PasswordGenerator

[![GitHub](https://img.shields.io/github/license/ed555009/utilities-password-generator)](LICENSE)
![Build Status](https://dev.azure.com/edwang/github/_apis/build/status/utilities-password-generator?branchName=main)
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
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public bool Verify()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// prepare password, hash and salt
		var data = new HashedPasswordModel
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
