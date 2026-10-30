using System.Text.Json;
using Lantern.Security;
using Lantern.PolicyEngine;

namespace Lantern.Service;

public sealed class MaintenanceRunner(AgentConfiguration config, LocalState state, AgentTransport transport)
{
    int verificationCursor;
    public async Task VerifyPending(CancellationToken token)
    {
        foreach(string file in Directory.EnumerateFiles(state.Root,"maintenance-*.result.json").Where(file=>!File.Exists(file+".reported")).Take(20))
        {
            if(File.Exists(file+".reported"))continue;
            string id=Path.GetFileName(file)[12..^12];
            if(!Guid.TryParse(id,out _))continue;
            using var result=JsonDocument.Parse(await File.ReadAllTextAsync(file,token));
            using var sent=await transport.Send(HttpMethod.Post,$"api/v1/agent/maintenance/{id}/result",result.RootElement,cancellationToken:token);
            sent.EnsureSuccessStatusCode();await File.WriteAllTextAsync(file+".reported","acknowledged",token);
        }
        using var response=await transport.Send(HttpMethod.Get,"api/v1/agent/maintenance/pending-verification",cancellationToken:token);
        response.EnsureSuccessStatusCode();using var parsed=JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
        var envelopes=parsed.RootElement.GetProperty("jobs").EnumerateArray().Select(x=>x.Clone()).ToArray();
        for(int index=0;index<Math.Min(2,envelopes.Length);index++)
        {
            var envelope=envelopes[(verificationCursor+index)%envelopes.Length];
            using var verified=SignedDocument.Verify(envelope.GetRawText(),config.SigningPublicKey);var ticket=verified.RootElement;
            if(ticket.GetProperty("purpose").GetString()!="verify_maintenance"||ticket.GetProperty("device_id").GetString()!=config.DeviceId||SignedDocument.UtcInstant(ticket.GetProperty("expires_at").GetString()!)<DateTime.UtcNow)throw new InvalidDataException("Invalid maintenance verification ticket.");
            string id=ticket.GetProperty("job_id").GetString()!;if(!Guid.TryParse(id,out _))throw new InvalidDataException("Invalid maintenance ID.");
            string file=$"maintenance-{id}.verify.json";await state.Save(file,ticket.GetRawText());
            var result=await PowerShell.Run("Service/Verify-Maintenance.ps1",["-ManifestFile",state.PathFor(file)],token);
            if(result.ExitCode!=0){await state.Log("maintenance.verification_unavailable",new{id,result.ExitCode});continue;}
            using var evidence=JsonDocument.Parse(result.Output);if(evidence.RootElement.GetProperty("state").GetString()=="WAITING")continue;
            using var sent=await transport.Send(HttpMethod.Post,$"api/v1/agent/maintenance/{id}/result",evidence.RootElement,cancellationToken:token);sent.EnsureSuccessStatusCode();
        }
        if(envelopes.Length>0)verificationCursor=(verificationCursor+2)%envelopes.Length;
    }

    public async Task RunNext(CancellationToken token)
    {
        using var next = await transport.Send(HttpMethod.Get, "api/v1/agent/maintenance/next", cancellationToken: token);
        next.EnsureSuccessStatusCode();
        using var response = JsonDocument.Parse(await next.Content.ReadAsStringAsync(token));
        if (response.RootElement.GetProperty("job").ValueKind == JsonValueKind.Null) return;
        using var manifest = SignedDocument.Verify(response.RootElement.GetProperty("job").GetRawText(), config.SigningPublicKey);
        var m = manifest.RootElement;
        if (m.GetProperty("device_id").GetString() != config.DeviceId || m.GetProperty("schema_version").GetInt32() != 1 || SignedDocument.UtcInstant(m.GetProperty("expires_at").GetString()!) < DateTime.UtcNow)
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
        string resultFile=$"maintenance-{id}.result.json";
        await state.Save(resultFile,JsonSerializer.Serialize(result,Json.Options));
        using var reported = await transport.Send(HttpMethod.Post, $"api/v1/agent/maintenance/{id}/result", result, cancellationToken: token);
        reported.EnsureSuccessStatusCode();
        await File.WriteAllTextAsync(state.PathFor(resultFile)+".reported","acknowledged",token);
        await state.Log("maintenance.result", new { id });
    }
}
