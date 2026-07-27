// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal static class Program
{
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    private static async Task<int> Main(string[] args)
    {
        GitRepository? repository = null;
        try
        {
            repository = GitRepository.Discover(Environment.CurrentDirectory);
            var arguments = new CommandArguments(args);
            if (arguments.Count == 0 || arguments.Is("help") || arguments.Has("--help") || arguments.Has("-h"))
            {
                PrintHelp();
                return 0;
            }

            return arguments[0].ToLowerInvariant() switch
            {
                "doctor" => await DoctorCommand.RunAsync(repository, arguments.Slice(1)),
                "index" => await SourceIndexCommand.RunAsync(repository, arguments.Slice(1)),
                "profile" => await ProfileCommand.RunAsync(repository, arguments.Slice(1)),
                "run" => await RunCommand.RunAsync(repository, arguments.Slice(1)),
                "visual" => await VisualCommand.RunAsync(repository, arguments.Slice(1)),
                "synthetic" => await SyntheticCommand.RunAsync(repository, arguments.Slice(1)),
                "game" => await GameInputCommand.RunAsync(repository, arguments.Slice(1)),
                "skills" => SkillCommand.Run(repository, arguments.Slice(1)),
                "redact" => await RunArtifactRedactor.RunAsync(repository, arguments.Slice(1)),
                _ => Fail($"Unknown command '{arguments[0]}'. Run with --help for usage."),
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation canceled.");
            return 130;
        }
        catch (Exception exception)
        {
            var message = repository is null
                ? exception.GetType().Name
                : RunArtifactRedactor.SanitizeMessage(exception.Message, repository);
            Console.Error.WriteLine($"agent-harness: {message}");
            return 1;
        }
    }

    internal static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }

    internal static void WriteJson<T>(T value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            SharpEmu agent harness

              agent-harness doctor [--profile <local-profile.json>] [--fast] [--environment-only] [--json]
              agent-harness index build|status [--json]
              agent-harness index query --symbol <name> [--namespace <name>] [--kind <kind>] [--limit 20] [--json]
              agent-harness index outline (--path <tracked-path> | --symbol <name>) [--limit 20] [--json]
              agent-harness index text --pattern <text> [--limit 20] [--json]
              agent-harness index map --project <name> [--json]
              agent-harness profile validate --profile <local-profile.json> [--fast] [--json]
              agent-harness run --profile <local-profile.json>
              agent-harness visual analyze --run <run-id-or-path> [--json]
              agent-harness visual compare --before <run-id-or-path> --after <run-id-or-path> [--frame <number>] [--exploratory] [--json]
              agent-harness synthetic visual [--output <directory>] [--json]
              agent-harness game inspect|extract|resume --metadata <phase-00-json> [--json]
              agent-harness skills validate [--json]
              agent-harness redact run --run <run-id-or-path> [--json]

            Output is bounded to 20 results by default. Add --json for machine-readable query output.
            Generated indexes, reports, runs, and images stay under .local/.
            """);
    }
}

internal sealed class CommandArguments
{
    private readonly string[] _values;

    public CommandArguments(IEnumerable<string> values) => _values = values.ToArray();

    public int Count => _values.Length;

    public string this[int index] => _values[index];

    public bool Is(string value) => Count > 0 && string.Equals(_values[0], value, StringComparison.OrdinalIgnoreCase);

    public bool Has(string option) => _values.Any(value => string.Equals(value, option, StringComparison.OrdinalIgnoreCase));

    public string? Value(string option)
    {
        for (var index = 0; index < _values.Length; index++)
        {
            var value = _values[index];
            if (string.Equals(value, option, StringComparison.OrdinalIgnoreCase))
            {
                return index + 1 < _values.Length ? _values[index + 1] : null;
            }

            var prefix = option + "=";
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return value[prefix.Length..];
            }
        }

        return null;
    }

    public int IntValue(string option, int fallback, int minimum = 1, int maximum = 10_000)
    {
        var text = Value(option);
        return int.TryParse(text, out var value) ? Math.Clamp(value, minimum, maximum) : fallback;
    }

    public CommandArguments Slice(int start) => new(_values.Skip(start));

    public IReadOnlyList<string> Values => _values;
}
