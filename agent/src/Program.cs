using Lantern.Enrollment;
using Lantern.Security;
using Lantern.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows is required.");
var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Lantern");
Directory.CreateDirectory(root);
var config = AgentConfiguration.Load(root);
if (args.Contains("--enroll"))
{
    await EnrollmentClient.Enroll(config, root);
    return;
}
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "LocalNetworkPolicyAgent");
builder.Logging.AddEventLog(o => o.SourceName = "LocalNetworkPolicyAgent");
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(new LocalState(root));
builder.Services.AddSingleton<AgentTransport>();
builder.Services.AddHostedService<PolicyWorker>();
await builder.Build().RunAsync();
