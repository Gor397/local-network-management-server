using System.Text.Json;
using Lantern.Security;
using Lantern.PolicyEngine;

namespace Lantern.Service;

public sealed class MaintenanceRunner(AgentConfiguration config, LocalState state, AgentTransport transport)
{
    public async Task RunNext(CancellationToken token)
    {
        using var next = await transport.Send(HttpMethod.Get, "api/v1/agent/maintenance/next", cancellationToken: token);
        next.EnsureSuccessStatusCode();
        using var response = JsonDocument.Parse(await next.Content.ReadAsStringAsync(token));
        if (response.RootElement.GetProperty("job").ValueKind == JsonValueKind.Null) return;
        using var manifest = SignedDocument.Verify(response.RootElement.GetProperty("job").GetRawText(), config.SigningPublicKey);
        var m = manifest.RootElement;
        if (m.GetProperty("device_id").GetString() != config.DeviceId || m.GetProperty("schema_version").GetInt32() != 1 || DateTime.Parse(m.GetProperty("expires_at").GetString()!).ToUniversalTime() < DateTime.UtcNow)
            throw new InvalidDataException("Maintenance authorization expired or mismatched.");
        string id = m.GetProperty("job_id").GetString()!;
        if (!Guid.TryParse(id, out _)) throw new InvalidDataException("Invalid maintenance identifier.");
        string script = m.GetProperty("operation").GetString() switch {
            "windows.locale" => "Deployment/Configure-Locale.ps1",
            "ssh.enable" => "Network/Enable-OpenSSH.ps1",
            "firewall.apply_allowlist" => "Firewall/Apply-Allowlist.ps1",
            "system.reboot" => "Service/Approved-Reboot.ps1",
            _ => throw new InvalidDataException("Unsupported maintenance operation.") };
        var filename = $"maintenance-{id}.json";
        var ledger = state.PathFor($"maintenance-{id}.started");
        object result;
        if (File.Exists(ledger)) result = new { state = "UNKNOWN", details = new { reason = "Previous execution requires inspection; not replayed." } };
        else
        {
            await state.Save(filename, m.GetRawText());
            await File.WriteAllTextAsync(ledger, DateTimeOffset.UtcNow.ToString("O"), token);
            var process = await PowerShell.Run(script, ["-ManifestFile", state.PathFor(filename)], token);
            if (process.ExitCode != 0) result = new { state = "FAILED", details = new { exit_code = process.ExitCode, error = process.Error[..Math.Min(2000, process.Error.Length)] } };
            else
            {
                using var parsed = JsonDocument.Parse(process.Output);
                result = parsed.RootElement.Clone();
            }
        }
        using var reported = await transport.Send(HttpMethod.Post, $"api/v1/agent/maintenance/{id}/result", result, cancellationToken: token);
        reported.EnsureSuccessStatusCode();
        await state.Log("maintenance.result", new { id });
    }
}
