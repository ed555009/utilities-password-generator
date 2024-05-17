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

## Add services(optional)

You can add the service to the DI container.

```csharp
using Utilities.PasswordGenerator.Interfaces;
using Utilities.PasswordGenerator.Services;

ConfigureServices(IServiceCollection services)
{
	// this injects as SINGLETON
	services.AddSingleton<IPasswordGeneratorService, PasswordGeneratorService>();
}
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

In case you don't want any special characters, you can set `specialChars` to empty string.

```csharp
using Utilities.PasswordGenerator.Services;

public class MyProcess
{
	public string Generate()
	{
		var passwordGeneratorService = new PasswordGeneratorService();

		// generate 16 characters password with at least 1 uppercase, 1 lowercase, 1 numeric and no special character
		return passwordGeneratorService.Generate(16, specialChars: "");
	}
}
```

### Use dependency injection

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
