using BenchmarkDotNet.Running;
using Utilities.PasswordGenerator.Benchmarks;

// Run: dotnet run -c Release -f net10.0 -- --filter '*' --runtimes net8.0 net10.0
_ = BenchmarkSwitcher.FromAssembly(typeof(PasswordGeneratorBenchmarks).Assembly).Run(args);
