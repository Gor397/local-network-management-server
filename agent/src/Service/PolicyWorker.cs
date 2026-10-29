using System.Net;
using System.Text.Json;
using Lantern.Security;
using Lantern.PolicyEngine;
using Lantern.Deployment;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Lantern.Service;

public sealed class PolicyWorker(AgentConfiguration config, LocalState state, AgentTransport transport,
    ILogger<PolicyWorker> logger) : BackgroundService
{
    string? etag;
    int failures;
    readonly DateTimeOffset started = DateTimeOffset.UtcNow;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var deployer = new DeploymentRunner(config, state, transport);
        var maintenance = new MaintenanceRunner(config, state, transport);
        Task activeDeployment = Task.CompletedTask;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Reconcile(stoppingToken);
                if (activeDeployment.IsCompleted)
                {
                    if (activeDeployment.IsFaulted) logger.LogWarning("Deployment background task failed; inspect durable execution ledger.");
                    await maintenance.RunNext(stoppingToken);
                    activeDeployment = deployer.RunNext(stoppingToken);
                }
                failures = 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                failures = Math.Min(failures + 1, 8);
                logger.LogWarning("Agent cycle failed: {ErrorType}", exception.GetType().Name);
                await state.Log("agent.cycle_failed", new { error = exception.GetType().Name, failures });
            }
            int seconds = Math.Min(900, config.PollSeconds * (1 << Math.Min(failures, 3)));
            try { await Task.Delay(TimeSpan.FromSeconds(seconds + Random.Shared.Next(0, 10)), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    async Task Reconcile(CancellationToken token)
    {
        string? version = null;
        if (File.Exists(state.PathFor("policy.envelope.json")))
        {
            using var cached = SignedDocument.Verify(await File.ReadAllTextAsync(state.PathFor("policy.envelope.json"), token), config.SigningPublicKey);
            version = cached.RootElement.GetProperty("version_id").GetString();
            if (DateTime.Parse(cached.RootElement.GetProperty("valid_until").GetString()!) < DateTime.UtcNow.AddHours(1)) etag = null;
        }
        using var heartbeat = await transport.Send(HttpMethod.Post, "api/v1/agent/heartbeat", new {
            agent_version = typeof(PolicyWorker).Assembly.GetName().Version?.ToString() ?? "0.1.0",
            os_version = Environment.OSVersion.VersionString, policy_version_id = version,
            health = new { uptime_seconds = (int)(DateTimeOffset.UtcNow - started).TotalSeconds, service_running = true }
        }, cancellationToken: token);
        heartbeat.EnsureSuccessStatusCode();
        using var response = await transport.Send(HttpMethod.Get, "api/v1/agent/policy", headers: etag is null ? null : new() { ["If-None-Match"] = etag }, cancellationToken: token);
        if (response.StatusCode == HttpStatusCode.NotFound) return;
        string envelope;
        if (response.StatusCode == HttpStatusCode.NotModified)
            envelope = await File.ReadAllTextAsync(state.PathFor("policy.envelope.json"), token);
        else
        {
            response.EnsureSuccessStatusCode();
            envelope = await response.Content.ReadAsStringAsync(token);
        }
        using var signed = SignedDocument.Verify(envelope, config.SigningPublicKey);
        SignedDocument.ValidatePolicy(signed.RootElement, config.DeviceId!);
        if (File.Exists(state.PathFor("policy.envelope.json")))
        {
            using var old = SignedDocument.Verify(await File.ReadAllTextAsync(state.PathFor("policy.envelope.json"), token), config.SigningPublicKey);
            if (signed.RootElement.GetProperty("revision").GetInt32() < old.RootElement.GetProperty("revision").GetInt32())
                throw new InvalidDataException("Policy revision rollback refused.");
        }
        await state.Save("policy.envelope.json", envelope);
        etag = response.Headers.ETag?.Tag ?? etag;
        var policy = signed.RootElement.GetProperty("document");
        version = signed.RootElement.GetProperty("version_id").GetString();
        await state.Save("policy.document.json", policy.GetRawText());
        var inspection = await Inspect(token);
        string mode = signed.RootElement.GetProperty("mode").GetString()!;
        if (mode is "CONTINUOUS" or "APPROVED_REMEDIATION")
        {
            foreach (var item in policy.GetProperty("auto_remediate").EnumerateArray())
            {
                string operation = item.GetString()!;
                string check = operation switch { "firewall.enable" => "firewall.enabled", "account.demote_user" => "account.user.not_administrator", "settings.hide_c" => "security.user_restrictions.valid", _ => throw new InvalidDataException("Unsupported remediation") };
                if (inspection.RootElement.GetProperty("claims").TryGetProperty(check, out var claim) && claim.GetProperty("status").GetString() == "FAIL")
                {
                    var result = await PowerShell.Run("PolicyEngine/Remediate.ps1", ["-Operation", operation, "-PolicyFile", state.PathFor("policy.document.json")], token);
                    await state.Log("remediation.executed", new { operation, result.ExitCode });
                    using var reported = await transport.Send(HttpMethod.Post, "api/v1/agent/remediation-result", new { policy_version_id = version, operation,
                        result = new { exit_code = result.ExitCode, error = result.Error[..Math.Min(result.Error.Length, 2000)] } }, cancellationToken: token);
                    reported.EnsureSuccessStatusCode();
                }
            }
            inspection.Dispose();
            inspection = await Inspect(token);
        }
        using (inspection)
        {
            using var compliance = await transport.Send(HttpMethod.Post, "api/v1/agent/compliance", new {
                policy_version_id = version, claims = inspection.RootElement.GetProperty("claims"), inventory = inspection.RootElement.GetProperty("inventory") }, cancellationToken: token);
            compliance.EnsureSuccessStatusCode();
            using var health = await transport.Send(HttpMethod.Post, "api/v1/agent/heartbeat", new {
                agent_version = typeof(PolicyWorker).Assembly.GetName().Version?.ToString(), os_version = Environment.OSVersion.VersionString,
                policy_version_id = version, health = inspection.RootElement.GetProperty("health") }, cancellationToken: token);
            health.EnsureSuccessStatusCode();
        }
        await state.Log("policy.assessed", new { version, mode });
    }

    async Task<JsonDocument> Inspect(CancellationToken token)
    {
        var result = await PowerShell.Run("Monitoring/Inspect.ps1", ["-PolicyFile", state.PathFor("policy.document.json"), "-AgentPath", Environment.ProcessPath!, "-Publisher", config.AgentPublisherThumbprint ?? ""], token);
        if (result.ExitCode != 0) throw new IOException("Windows inspection failed.");
        return JsonDocument.Parse(result.Output);
    }
}
