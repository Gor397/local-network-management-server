using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Lantern.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Lantern.Enrollment;

public sealed class IdentityPipeService(LocalState state, AgentTransport transport, ILogger<IdentityPipeService> logger) : BackgroundService
{
    public const string PipeName="Suro.Identity.v1";
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientSessionId(IntPtr handle,out uint session);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientProcessId(IntPtr handle,out uint process);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(state.PathFor("identities"));
        while(!stoppingToken.IsCancellationRequested)
        {
            var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));
            try
            {
                using var pipe=NamedPipeServerStreamAcl.Create(PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,8192,8192,security);
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);timeout.CancelAfter(TimeSpan.FromSeconds(15));
                if(!GetNamedPipeClientSessionId(pipe.SafePipeHandle.DangerousGetHandle(),out var session)||session==0
                    || !GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out _))continue;
                byte[] header=new byte[4];await pipe.ReadExactlyAsync(header,timeout.Token);int count=BitConverter.ToInt32(header);
                if(count<2||count>8192)continue;
                byte[] bytes=new byte[count];await pipe.ReadExactlyAsync(bytes,timeout.Token);
                // Windows impersonates the security context of the last message read.
                string? sid=null,account=null;
                pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent(true);sid=identity?.User?.Value;account=identity?.Name;});
                if(sid is null||!Regex.IsMatch(sid,"^S-1-5-[0-9-]{1,160}$"))continue;
                using var input=JsonDocument.Parse(bytes);string? operation=input.RootElement.GetProperty("operation").GetString();
                object result;
                string filename="identities/"+sid+".json";
                if(operation=="status")
                {
                    bool submitted=File.Exists(state.PathFor(filename));
                    if(!submitted)
                    {
                        using var probe=CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                        probe.CancelAfter(TimeSpan.FromSeconds(5));
                        try
                        {
                            using var response=await transport.Send(HttpMethod.Get,"api/v1/agent/identity-status?windows_sid="+Uri.EscapeDataString(sid),cancellationToken:probe.Token);
                            if(response.IsSuccessStatusCode){using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync(probe.Token));submitted=json.RootElement.GetProperty("submitted").GetBoolean();}
                        }catch(HttpRequestException){}
                        catch(OperationCanceledException)when(!timeout.IsCancellationRequested){}
                    }
                    result=new {submitted,default_language="hy"};
                }
                else if(operation=="submit")
                {
                    string name=input.RootElement.GetProperty("full_name").GetString()?.Trim()??"";
                    string? rank=input.RootElement.TryGetProperty("military_rank",out var field)?field.GetString()?.Trim():null;
                    bool noRank=input.RootElement.TryGetProperty("no_military_rank",out var absent)&&absent.GetBoolean();
                    if(name.Length<2||name.Length>256||name.Any(char.IsControl)||(rank?.Length??0)>128||(rank?.Any(char.IsControl)??false))throw new InvalidDataException("identity.invalid_text");
                    // The service obtains account/SID from the authenticated pipe token, never from UI JSON.
                    await state.Save(filename,JsonSerializer.Serialize(new {windows_sid=sid,windows_account=account,full_name=name,
                        military_rank=noRank?null:rank,no_military_rank=noRank},Json.Options));
                    File.Delete(state.PathFor(filename)+".sent");
                    result=new {accepted=true,status="USER_REPORTED_PENDING_SYNC"};
                }
                else throw new InvalidDataException("identity.unsupported_operation");
                byte[] reply=JsonSerializer.SerializeToUtf8Bytes(result,Json.Options);await pipe.WriteAsync(BitConverter.GetBytes(reply.Length),timeout.Token);await pipe.WriteAsync(reply,timeout.Token);await pipe.FlushAsync(timeout.Token);
            }
            catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){break;}
            catch(Exception exception)
            {
                logger.LogWarning("Identity UI request failed: {Type}",exception.GetType().Name);
                try { await Task.Delay(TimeSpan.FromSeconds(5),stoppingToken); } catch(OperationCanceledException){break;}
            }
        }
    }

    public static async Task Flush(LocalState state,AgentTransport transport,CancellationToken token)
    {
        string root=state.PathFor("identities");if(!Directory.Exists(root))return;
        foreach(var path in Directory.EnumerateFiles(root,"*.json").Take(10))
        {
            string payload=await File.ReadAllTextAsync(path,token);
            string hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(payload)));
            if(File.Exists(path+".sent")&&await File.ReadAllTextAsync(path+".sent",token)==hash)continue;
            using var document=JsonDocument.Parse(payload);
            using var response=await transport.Send(HttpMethod.Post,"api/v1/agent/identity",document.RootElement,cancellationToken:token);
            // A concurrent user correction must not be acknowledged by an older in-flight upload.
            if(response.IsSuccessStatusCode)await File.WriteAllTextAsync(path+".sent",hash,token);
        }
    }
}
