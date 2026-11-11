using System.Diagnostics;
using System.Text.Json;
using Azure;
using Azure.Identity;
using Microsoft.Azure.ContainerApps.Sandbox;
using Microsoft.Azure.ContainerApps.Sandbox.Models;

return await Demo.RunAsync(args);

internal sealed record Settings(string Subscription, string ResourceGroup, string Region, string Group, string? EnvFile);

internal sealed class Demo
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };
    readonly Settings settings;
    readonly SandboxGroupClient group;
    readonly string runId = Guid.NewGuid().ToString("N");
    readonly List<string> owned = [];
    readonly object manifestLock = new();

    Demo(Settings settings)
    {
        this.settings = settings;
        group = new SandboxGroupClient(settings.Region, settings.Subscription, settings.ResourceGroup,
            settings.Group, new AzureCliCredential());
    }

    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            string command = args.FirstOrDefault() ?? "help";
            if (command == "help")
            {
                Console.WriteLine("Commands: setup | model-check | demo [document.txt] | security | identity | scale [count] [concurrency] | cleanup | self-test");
                return 0;
            }
            if (command == "self-test")
            {
                EvidenceSelfTest();
                Console.WriteLine("Security evidence classification: passed.");
                return 0;
            }
            Directory.CreateDirectory(".demo");
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(".demo", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Settings settings = LoadSettings();
            LoadEnvironment(Environment.GetEnvironmentVariable("DEMO_ENV_FILE") ?? settings.EnvFile);
            var demo = new Demo(settings);
            if (command == "setup")
            {
                await demo.AcaAsync("sandboxgroup", "create", "--name", settings.Group, "--location", settings.Region);
                await demo.AssertIdentityAsync(false);
                await ProcessAsync("dotnet", ["publish", "src/LoanTool", "-c", "Release", "--verbosity", "quiet"]);
                demo.Trace("setup", new { group = settings.Group, region = settings.Region, identity = "disabled" });
                return 0;
            }
            if (command == "model-check")
            {
                string response = await Agent.ReplyAsync();
                demo.Trace("model", new { outcome = "live-response", model = Environment.GetEnvironmentVariable("AI_GATEWAY_MODEL") });
                Console.WriteLine(response);
                return 0;
            }
            if (command == "cleanup")
            {
                await demo.CleanupAllAsync();
                return 0;
            }
            try
            {
                switch (command)
                {
                    case "demo":
                        await demo.AssertIdentityAsync(false);
                        string path = args.ElementAtOrDefault(1) ?? "samples/loan-application.txt";
                        Console.WriteLine(await Agent.ReplyAsync(async () => (await demo.DocumentAsync(path)).GetRawText()));
                        break;
                    case "security":
                        await demo.SecurityAsync();
                        break;
                    case "identity":
                        await demo.IdentityAsync();
                        break;
                    case "scale":
                        int count = args.Length > 1 ? int.Parse(args[1]) : 100;
                        int concurrency = args.Length > 2 ? int.Parse(args[2]) : 10;
                        if (count is < 1 or > 100 || concurrency is < 1 or > 20)
                            throw new ArgumentException("Scale accepts 1..100 sandboxes and concurrency 1..20.");
                        await demo.ScaleAsync(count, concurrency);
                        break;
                    default:
                        throw new ArgumentException("Unknown command. Run dotnet run -- help.");
                }
            }
            finally
            {
                await demo.CleanupOwnedAsync();
            }
            return 0;
        }
        catch (Exception ex)
        {
            string detail = ex is RequestFailedException request ? $"Azure HTTP {request.Status}; code {request.ErrorCode}" :
                ex is InvalidOperationException or ArgumentException ? ex.Message : ex.GetType().Name;
            Console.Error.WriteLine($"FAILED: {Redact(detail)}");
            return 1;
        }
    }

    static string Redact(string text)
    {
        foreach (string key in new[] { "AI_GATEWAY_API_KEY", "AZURE_AI_GATEWAY_API_KEY", "GH_TOKEN", "GITHUB_TOKEN" })
            if (Environment.GetEnvironmentVariable(key) is { Length: > 0 } value) text = text.Replace(value, "[REDACTED]");
        return text.Length <= 800 ? text : text[..800];
    }

    static Settings LoadSettings()
    {
        const string file = ".demo/settings.json";
        if (File.Exists(file))
            return JsonSerializer.Deserialize<Settings>(File.ReadAllText(file), Json) ?? throw new InvalidOperationException("Invalid local settings.");
        using var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config/aca/config.json")));
        var root = config.RootElement;
        var settings = new Settings(root.GetProperty("subscription").GetString()!,
            root.GetProperty("resource_group").GetString()!, root.GetProperty("region").GetString()!,
            "dotnet-demo-" + Guid.NewGuid().ToString("N")[..6], Environment.GetEnvironmentVariable("DEMO_ENV_FILE"));
        File.WriteAllText(file, JsonSerializer.Serialize(settings, Json));
        return settings;
    }

    static void LoadEnvironment(string? path)
    {
        path ??= File.Exists(".env") ? ".env" : null;
        if (path is null) return;
        string[] allowed = ["AI_GATEWAY_BASE_URL", "AI_GATEWAY_MODEL", "AI_GATEWAY_API_KEY"];
        foreach (string line in File.ReadLines(path))
        {
            string entry = line.Trim();
            if (entry.StartsWith("export ")) entry = entry[7..];
            int equals = entry.IndexOf('=');
            if (equals <= 0) continue;
            string name = entry[..equals].Trim();
            if (!allowed.Contains(name) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name))) continue;
            string value = entry[(equals + 1)..].Trim();
            if (value.Length >= 2 && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
                value = value[1..^1];
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    void Trace(string stage, object evidence)
    {
        string line = JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, run = runId, stage, evidence }, Json);
        lock (manifestLock)
        {
            Console.WriteLine($"[{stage}] {JsonSerializer.Serialize(evidence, Json)}");
            File.AppendAllText(".demo/trace.jsonl", line + Environment.NewLine);
        }
    }

    async Task<string> AcaAsync(params string[] args) => await ProcessAsync("aca",
        [.. args, "--subscription", settings.Subscription, "--resource-group", settings.ResourceGroup,
            "--region", settings.Region, "--output", "json"]);

    static async Task<string> ProcessAsync(string executable, string[] arguments)
    {
        var start = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not launch {executable}.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw new TimeoutException($"{executable} timed out."); }
        string output = await stdout;
        string error = await stderr;
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"{executable} exited {process.ExitCode}: {Redact(error)}");
        return output;
    }

    async Task AssertIdentityAsync(bool enabled)
    {
        using var result = JsonDocument.Parse(await AcaAsync("sandboxgroup", "identity", "show", "--group", settings.Group));
        bool actual = result.RootElement.ValueKind != JsonValueKind.Null
            && result.RootElement.TryGetProperty("type", out var type)
            && type.GetString() is { } value && !value.Equals("None", StringComparison.OrdinalIgnoreCase);
        if (actual != enabled) throw new InvalidOperationException("Group identity state does not match the requested test mode.");
        Trace("group-identity", new { enabled });
    }

    void SaveManifest()
    {
        string path = $".demo/run-{runId}.json";
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(owned, Json));
        File.Move(temp, path, overwrite: true);
    }

    async Task<SandboxResource> CreateAsync()
    {
        var watch = Stopwatch.StartNew();
        var content = new CreateSandboxContent
        {
            SourcesRef = new SandboxSource { DiskImage = new SandboxSourceDiskImage { Name = "dotnet-10", IsPublic = true } },
            Resources = new SandboxResources("1000m", "2048Mi"),
            EgressPolicy = new SandboxEgressPolicy { DefaultAction = EgressPolicyAction.Deny, TrafficInspection = TrafficInspection.Full }
        };
        content.Labels["demo"] = "dotnet-loans";
        content.Labels["run"] = runId;
        SandboxResource sandbox = (await group.CreateSandboxAsync(content)).Value;
        lock (manifestLock) { owned.Add(sandbox.Id); SaveManifest(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        while (true)
        {
            var current = (await sandbox.GetAsync(timeout.Token)).Value;
            string state = current.Data?.State.ToString()
                ?? throw new InvalidOperationException("Sandbox readiness response omitted its state.");
            if (state.Equals("Running", StringComparison.OrdinalIgnoreCase)) break;
            if (state is "Failed" or "Deleted" or "Stopped") throw new InvalidOperationException("Sandbox failed to reach Running.");
            await Task.Delay(500, timeout.Token);
        }
        Trace("sandbox-running", new { sandbox = sandbox.Id, runtime = "dotnet-10", egress = "Deny", elapsedMs = watch.ElapsedMilliseconds });
        return sandbox;
    }

    async Task UploadToolAsync(SandboxResource sandbox)
    {
        const string directory = "src/LoanTool/bin/Release/net10.0/publish";
        foreach (string name in new[] { "LoanTool.dll", "LoanTool.deps.json", "LoanTool.runtimeconfig.json" })
        {
            using var stream = File.OpenRead(Path.Combine(directory, name));
            var result = (await sandbox.WriteSandboxFileAsync("/workspace/" + name, stream, createDirs: true)).Value;
            if (!result.Success) throw new InvalidOperationException("Tool upload failed.");
        }
        var runtime = await ToolAsync(sandbox, "runtime");
        string description = runtime.GetProperty("runtime").GetString()!;
        if (!description.StartsWith(".NET 10.", StringComparison.Ordinal))
            throw new InvalidOperationException("The sandbox is not running .NET 10.");
        Trace("runtime", new { sandbox = sandbox.Id, runtime = description });
    }

    async Task<JsonElement> ToolAsync(SandboxResource sandbox, params string[] arguments)
    {
        var command = new ExecuteSandboxCommandContent("dotnet");
        command.Arguments.Add("/workspace/LoanTool.dll");
        foreach (string argument in arguments) command.Arguments.Add(argument);
        var result = (await sandbox.ExecuteCommandAsync(command)).Value;
        if (result.ExitCode != 0) throw new InvalidOperationException($"Sandbox tool failed with exit {result.ExitCode}; payload omitted.");
        if (result.StandardOutput is null || result.StandardOutput.Length > 32_768)
            throw new InvalidOperationException("Tool output violated the bounded contract.");
        using var parsed = JsonDocument.Parse(result.StandardOutput);
        return parsed.RootElement.Clone();
    }

    async Task<JsonElement> DocumentAsync(string path)
    {
        await AssertIdentityAsync(false);
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is not (".txt" or ".md") || new FileInfo(path).Length > 65_536)
            throw new ArgumentException("Select a UTF-8 .txt or .md document of at most 64 KiB.");
        var sandbox = await CreateAsync();
        await UploadToolAsync(sandbox);
        using (var stream = File.OpenRead(path))
        {
            var upload = (await sandbox.WriteSandboxFileAsync("/workspace/input" + extension, stream, createDirs: true)).Value;
            if (!upload.Success) throw new InvalidOperationException("Document upload failed.");
        }
        var result = await ToolAsync(sandbox, "process", "/workspace/input" + extension);
        CheckIsolation(result.GetProperty("isolation"));
        Trace("document", new { sandbox = sandbox.Id, verdict = result.GetProperty("verdict").GetString(),
            reason = result.GetProperty("reason").GetString(), rawDocumentReturned = false,
            redactions = result.TryGetProperty("redactions", out var redactions) ? (JsonElement?)redactions : null });
        return result;
    }

    static void CheckIsolation(JsonElement isolation)
    {
        if (isolation.GetProperty("hostCredentialVariablesPresent").GetInt32() != 0
            || isolation.GetProperty("credentialLocationsPresent").GetInt32() != 0
            || isolation.GetProperty("credentialValuesReturned").GetBoolean())
            throw new InvalidOperationException("Credential isolation check failed.");
    }

    async Task SecurityAsync()
    {
        await AssertIdentityAsync(false);
        var rejected = await DocumentAsync("samples/adversarial-loan.txt");
        if (rejected.GetProperty("verdict").GetString() != "rejected")
            throw new InvalidOperationException("Adversarial document was not rejected.");
        var sandbox = await CreateAsync();
        await UploadToolAsync(sandbox);
        var probe = await ToolAsync(sandbox, "probe-egress");
        CheckIsolation(probe.GetProperty("isolation"));
        Trace("egress-probe", probe);
        int? probeStatus = HttpStatus(probe);
        for (int attempt = 0; attempt < 15; attempt++)
        {
            var decisions = (await sandbox.GetEgressDecisionsAsync(CancellationToken.None)).Value;
            var denial = decisions.Http?.Denied.FirstOrDefault(d => d.Host == "example.com" && d.Method == "HEAD" && d.Path == "/");
            if (EgressDenied(probeStatus, denial is not null))
            {
                Trace("security-pass", new { sandbox = sandbox.Id, test = "egress-and-secret-isolation",
                    enforcement = "aca-egress-proxy", host = "example.com", method = "HEAD",
                    path = "/", matchedRule = denial?.MatchedRule, hostCredentialsPresent = false });
                return;
            }
            await Task.Delay(1000);
        }
        throw new InvalidOperationException("No matching ACA deny decision; egress enforcement is inconclusive.");
    }

    async Task IdentityAsync()
    {
        await AssertIdentityAsync(false);
        try
        {
            await IdentityProbeAsync(false);
            await AcaAsync("sandboxgroup", "identity", "assign", "--group", settings.Group, "--system-assigned");
            await AssertIdentityAsync(true);
            await IdentityProbeAsync(true);
        }
        finally
        {
            await AcaAsync("sandboxgroup", "identity", "remove", "--group", settings.Group, "--system-assigned");
            await AssertIdentityAsync(false);
        }
        await IdentityProbeAsync(false);
    }

    async Task IdentityProbeAsync(bool enabled)
    {
        var sandbox = await CreateAsync();
        await UploadToolAsync(sandbox);
        for (int attempt = 0; attempt < 15; attempt++)
        {
            var result = await ToolAsync(sandbox, "probe-identity");
            bool issued = result.GetProperty("tokenIssued").GetBoolean();
            int? status = HttpStatus(result);
            if (IdentityMatches(enabled, status, issued))
            {
                Trace("identity-pass", new { sandbox = sandbox.Id, groupMiEnabled = enabled, httpStatus = status,
                    tokenIssued = issued, tokenValue = "[REDACTED]", isolation = result.GetProperty("isolation") });
                return;
            }
            await Task.Delay(1000);
        }
        throw new InvalidOperationException($"Identity probe did not establish the expected MI {(enabled ? "ON" : "OFF")} result.");
    }

    static int? HttpStatus(JsonElement result)
    {
        var status = result.GetProperty("httpStatus");
        return status.ValueKind == JsonValueKind.Null ? null : status.GetInt32();
    }

    static bool EgressDenied(int? status, bool matchedPlatformDenial) =>
        matchedPlatformDenial && status is null or 403;

    static bool IdentityMatches(bool enabled, int? status, bool tokenIssued) =>
        enabled ? tokenIssued && status == 200 : !tokenIssued && status is 400 or 401 or 403;

    static void EvidenceSelfTest()
    {
        static void Check(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException("Security evidence regression: " + name);
        }
        Check(!EgressDenied(null, false) && !EgressDenied(403, false), "transport failures and unmatched 403s are inconclusive");
        Check(EgressDenied(403, true) && EgressDenied(null, true), "matching platform denial");
        Check(!EgressDenied(200, true), "conflicting successful HTTP response");
        Check(IdentityMatches(false, 401, false) && IdentityMatches(true, 200, true), "expected identity states");
        Check(!IdentityMatches(false, null, false), "missing identity plumbing is inconclusive");
        Check(!IdentityMatches(false, 401, true) && !IdentityMatches(true, 200, false), "token issuance must match HTTP and group state");
        using var missing = JsonDocument.Parse("""{"httpStatus":null}""");
        Check(HttpStatus(missing.RootElement) is null, "null HTTP status");
    }

    async Task ScaleAsync(int count, int concurrency)
    {
        await AssertIdentityAsync(false);
        var watch = Stopwatch.StartNew();
        int success = 0, failed = 0;
        using var limit = new SemaphoreSlim(concurrency);
        await Task.WhenAll(Enumerable.Range(0, count).Select(async _ =>
        {
            await limit.WaitAsync();
            try
            {
                var sandbox = await CreateAsync();
                await UploadToolAsync(sandbox);
                Interlocked.Increment(ref success);
            }
            catch (Exception ex) when (ex is RequestFailedException or InvalidOperationException or OperationCanceledException)
            {
                Interlocked.Increment(ref failed);
                Trace("scale-failure", new { error = ex.GetType().Name, httpStatus = ex is RequestFailedException request ? request.Status : (int?)null });
            }
            finally { limit.Release(); }
        }));
        Trace("scale-summary", new { requested = count, runningDotnetVerified = success, failed,
            elapsedMs = watch.ElapsedMilliseconds, verifiedPerSecond = success / watch.Elapsed.TotalSeconds });
        if (failed > 0) throw new InvalidOperationException("Scale batch was partially unsuccessful. See sanitized scale-failure events.");
    }

    async Task CleanupOwnedAsync()
    {
        int failed = 0;
        await Parallel.ForEachAsync(owned.ToArray(), new ParallelOptions { MaxDegreeOfParallelism = 10 }, async (id, _) =>
        {
            try { await group.GetSandboxResource(id).DeleteAsync(); }
            catch (RequestFailedException ex) when (ex.Status == 404) { }
            catch (Exception ex)
            {
                Interlocked.Increment(ref failed);
                Trace("cleanup-failure", new { sandbox = id, error = ex.GetType().Name });
                return;
            }
            lock (manifestLock) { owned.Remove(id); SaveManifest(); }
            Trace("sandbox-deleted", new { sandbox = id });
        });
        if (failed > 0) throw new InvalidOperationException("Sandbox cleanup was incomplete. Run dotnet run -- cleanup.");
        string path = $".demo/run-{runId}.json";
        if (File.Exists(path)) File.Delete(path);
    }

    async Task CleanupAllAsync()
    {
        await AcaAsync("sandboxgroup", "identity", "remove", "--group", settings.Group, "--system-assigned");
        await AssertIdentityAsync(false);
        await foreach (var sandbox in group.GetSandboxesAsync(labels: new Dictionary<string, string> { ["demo"] = "dotnet-loans" }))
            owned.Add(sandbox.Id);
        await CleanupOwnedAsync();
    }
}
