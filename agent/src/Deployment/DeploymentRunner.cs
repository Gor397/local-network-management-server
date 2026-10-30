using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Lantern.Security;
using Lantern.PolicyEngine;
using Lantern.Service;

namespace Lantern.Deployment;

public sealed class DeploymentRunner(AgentConfiguration config, LocalState state, AgentTransport transport)
{
    public async Task RunNext(CancellationToken token)
    {
        using var next = await transport.Send(HttpMethod.Get, "api/v1/agent/deployments/next", cancellationToken: token);
        next.EnsureSuccessStatusCode();
        using var response = JsonDocument.Parse(await next.Content.ReadAsStringAsync(token));
        var task = response.RootElement.GetProperty("task");
        if (task.ValueKind == JsonValueKind.Null) return;
        using var manifest = SignedDocument.Verify(task.GetRawText(), config.SigningPublicKey);
        var m = manifest.RootElement;
        if (m.GetProperty("schema_version").GetInt32() != 1 || m.GetProperty("device_id").GetString() != config.DeviceId
            || SignedDocument.UtcInstant(m.GetProperty("expires_at").GetString()!) < DateTime.UtcNow)
            throw new InvalidDataException("Deployment authorization invalid.");
        string id = m.GetProperty("task_id").GetString()!;
        int attempt = m.GetProperty("attempt").GetInt32();
        string ledger = $"deployment-{id}-{attempt}.json";
        if (File.Exists(state.PathFor(ledger)))
        {
            using var prior = JsonDocument.Parse(await File.ReadAllTextAsync(state.PathFor(ledger), token));
            if (prior.RootElement.GetProperty("state").GetString() == "RUNNING")
            {
                await Report(id, new { attempt, state = "UNKNOWN", verified = false, log_tail = "Service restarted during installation; inspect before retry." }, token);
                return;
            }
            await Report(id, prior.RootElement, token);
            return;
        }
        try
        {
            string sha = m.GetProperty("sha256").GetString()!;
            if (!System.Text.RegularExpressions.Regex.IsMatch(sha, "^[a-f0-9]{64}$")) throw new InvalidDataException("Invalid package hash.");
            string filename = m.GetProperty("filename").GetString()!;
            if (Path.GetFileName(filename) != filename) throw new InvalidDataException("Unsafe filename.");
            string cache = state.PathFor("packages"); Directory.CreateDirectory(cache);
            string package = Path.Combine(cache, sha + Path.GetExtension(filename));
            await Download(m.GetProperty("package_id").GetString()!, sha, m.GetProperty("size").GetInt64(), package, token);
            using var check = await transport.Send(HttpMethod.Get, $"api/v1/agent/deployments/{id}", cancellationToken: token);
            check.EnsureSuccessStatusCode();
            using var checkDocument = JsonDocument.Parse(await check.Content.ReadAsStringAsync(token));
            if (checkDocument.RootElement.GetProperty("cancel_requested").GetBoolean())
            {
                await Report(id, new { attempt, state = "CANCELLED", verified = false }, token);
                return;
            }
            if(checkDocument.RootElement.GetProperty("state").GetString()!="RUNNING" || SignedDocument.UtcInstant(m.GetProperty("expires_at").GetString()!)<DateTime.UtcNow)
                throw new InvalidDataException("Installation authorization expired during download.");
            string manifestPath = state.PathFor($"deployment-{id}.manifest.json");
            await state.Save($"deployment-{id}.manifest.json", m.GetRawText());
            await state.Save(ledger, JsonSerializer.Serialize(new { state = "RUNNING", attempt }));
            // MSI agent updates cannot stop their own service safely; use the external update task.
            string script = m.GetProperty("kind").GetString() == "agent_update" ? "Deployment/Stage-AgentUpdate.ps1" : "Deployment/Install.ps1";
            var result = await PowerShell.Run(script, ["-ManifestFile", manifestPath, "-PackageFile", package], token);
            object reported;
            if (result.ExitCode == 0)
            {
                using var parsed = JsonDocument.Parse(result.Output);
                reported = new { attempt, state = parsed.RootElement.GetProperty("state").GetString(),
                    exit_code = parsed.RootElement.GetProperty("exit_code").GetInt32(), verified = parsed.RootElement.GetProperty("verified").GetBoolean(),
                    details=parsed.RootElement.TryGetProperty("details",out var details)?details.Clone():JsonSerializer.SerializeToElement(new{}),
                    log_tail = result.Error[..Math.Min(16000, result.Error.Length)] };
            }
            else reported = new { attempt, state = "FAILED", exit_code = result.ExitCode, verified = false, log_tail = result.Error[..Math.Min(16000, result.Error.Length)] };
            string record = JsonSerializer.Serialize(reported, Json.Options);
            await state.Save(ledger, record);
            await Report(id, reported, token);
            await File.WriteAllTextAsync(state.PathFor(ledger)+".reported","acknowledged",token);
            await state.Log("deployment.finished", new { id, attempt, result.ExitCode });
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            // RUNNING ledger survives failures; an interrupted install is never blindly replayed.
            await state.Log("deployment.failed", new { id, attempt, error = exception.GetType().Name });
            await Report(id, new { attempt, state = "FAILED", verified = false, log_tail = exception.GetType().Name }, token);
        }
    }

    async Task Report(string id, object result, CancellationToken token)
    {
        using var response = await transport.Send(HttpMethod.Post, $"api/v1/agent/deployments/{id}/result", result, cancellationToken: token);
        response.EnsureSuccessStatusCode();
    }

    async Task Download(string id, string hash, long size, string destination, CancellationToken token)
    {
        if (File.Exists(destination))
        {
            using var cached = File.OpenRead(destination);
            if (Convert.ToHexString(await SHA256.HashDataAsync(cached, token)).Equals(hash, StringComparison.OrdinalIgnoreCase)) return;
            throw new InvalidDataException("Cached package integrity failure.");
        }
        string partial = destination + ".partial";
        long offset = File.Exists(partial) ? new FileInfo(partial).Length : 0;
        if (offset > size) throw new InvalidDataException("Partial download exceeds expected size.");
        if (offset < size)
        {
            HttpResponseMessage response;
            int retries=0;
            while(true)
            {
                response=await transport.Send(HttpMethod.Get,$"api/v1/agent/packages/{id}",headers:offset>0?new(){["Range"]=$"bytes={offset}-"}:null,streaming:true,cancellationToken:token);
                if((response.StatusCode!=HttpStatusCode.TooManyRequests&&response.StatusCode!=HttpStatusCode.ServiceUnavailable)||retries>=5)break;
                response.Dispose();await Task.Delay(TimeSpan.FromSeconds(Math.Min(30,2<<retries++)),token);
            }
            using var ownedResponse=response;
            response.EnsureSuccessStatusCode();
            if (offset > 0 && (response.StatusCode != HttpStatusCode.PartialContent || response.Content.Headers.ContentRange?.From != offset))
                throw new InvalidDataException("Download resume range mismatch.");
            await using var stream = await response.Content.ReadAsStreamAsync(token);
            await using var output = new FileStream(partial, FileMode.Append, FileAccess.Write, FileShare.None, 65536, true);
            byte[] buffer = new byte[65536]; int read; long written = offset;
            while ((read = await stream.ReadAsync(buffer, token)) > 0)
            {
                written += read;
                if (written > size) throw new InvalidDataException("Package download exceeds manifest size.");
                await output.WriteAsync(buffer.AsMemory(0, read), token);
            }
        }
        using (var source = File.OpenRead(partial))
            if (source.Length != size || !Convert.ToHexString(await SHA256.HashDataAsync(source, token)).Equals(hash, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Downloaded package hash mismatch.");
        File.Move(partial, destination, true);
    }
}
