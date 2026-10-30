using System.Text.Json;
using System.Text.RegularExpressions;
using Lantern.Security;
using Lantern.PolicyEngine;
using Lantern.Service;

namespace Lantern.Deployment;

public sealed class DeploymentVerifier(AgentConfiguration config,LocalState state,AgentTransport transport)
{
    int cursor;
    bool startup=true;
    public async Task Run(CancellationToken token)
    {
        // A protected durable result is retried until acknowledged; an interrupted installer is never rerun.
        foreach(string path in Directory.EnumerateFiles(state.Root,"deployment-*.json").Where(path=>!File.Exists(path+".reported")).Take(20))
        {
            var match=Regex.Match(Path.GetFileName(path),@"^deployment-([0-9a-fA-F-]{36})-(\d+)\.json$");
            if(!match.Success||File.Exists(path+".reported"))continue;
            using var saved=JsonDocument.Parse(await File.ReadAllTextAsync(path,token));
            string? status=saved.RootElement.GetProperty("state").GetString();
            if(status=="RUNNING")
            {
                if(!startup)continue;
                string manifestPath=state.PathFor($"deployment-{match.Groups[1].Value}.manifest.json");
                if(File.Exists(manifestPath))
                {
                    using var manifest=JsonDocument.Parse(await File.ReadAllTextAsync(manifestPath,token));
                    if(manifest.RootElement.GetProperty("kind").GetString()=="agent_update")continue;
                }
                var ambiguous=new{attempt=int.Parse(match.Groups[2].Value),state="UNKNOWN",verified=false,log_tail="Interrupted privileged execution requires review; it was not replayed."};
                await state.Save(Path.GetFileName(path),JsonSerializer.Serialize(ambiguous,Json.Options));
                await Send(match.Groups[1].Value,ambiguous,token);
            }
            else await Send(match.Groups[1].Value,saved.RootElement,token);
            await File.WriteAllTextAsync(path+".reported","acknowledged",token);
        }
        startup=false;
        using var response=await transport.Send(HttpMethod.Get,"api/v1/agent/deployments/pending-verification",cancellationToken:token);
        response.EnsureSuccessStatusCode();
        using var body=JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
        var tickets=body.RootElement.GetProperty("tasks").EnumerateArray().Select(x=>x.Clone()).ToArray();
        for(int i=0;i<Math.Min(2,tickets.Length);i++)
        {
            using var document=SignedDocument.Verify(tickets[(cursor+i)%tickets.Length].GetRawText(),config.SigningPublicKey);
            var ticket=document.RootElement;
            if(ticket.GetProperty("purpose").GetString()!="verify_deployment"||ticket.GetProperty("device_id").GetString()!=config.DeviceId||SignedDocument.UtcInstant(ticket.GetProperty("expires_at").GetString()!)<DateTime.UtcNow)
                throw new InvalidDataException("Invalid deployment verification authorization.");
            string id=ticket.GetProperty("task_id").GetString()!;
            if(!Guid.TryParse(id,out _))throw new InvalidDataException("Invalid deployment identifier.");
            string file=$"verify-{id}.json";await state.Save(file,ticket.GetRawText());
            var result=await PowerShell.Run("Deployment/Verify.ps1",["-ManifestFile",state.PathFor(file)],token);
            if(result.ExitCode!=0){await state.Log("deployment.verification_unavailable",new{id,result.ExitCode});continue;}
            using var parsed=JsonDocument.Parse(result.Output);
            string status=parsed.RootElement.GetProperty("state").GetString()!;
            if(status=="WAITING")continue;
            var report=new{attempt=ticket.GetProperty("attempt").GetInt32(),state=status,verified=parsed.RootElement.GetProperty("verified").GetBoolean(),details=parsed.RootElement.GetProperty("details")};
            await Send(id,report,token);
            string ledger=$"deployment-{id}-{report.attempt}.json";
            await state.Save(ledger,JsonSerializer.Serialize(report,Json.Options));
            await File.WriteAllTextAsync(state.PathFor(ledger)+".reported","acknowledged",token);
        }
        if(tickets.Length>0)cursor=(cursor+2)%tickets.Length;
    }
    async Task Send(string id,object body,CancellationToken token)
    {
        using var response=await transport.Send(HttpMethod.Post,$"api/v1/agent/deployments/{id}/result",body,cancellationToken:token);
        response.EnsureSuccessStatusCode();
    }
}
