using Lantern.Enrollment;
using Lantern.Security;
using Lantern.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows is required.");
var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Lantern");
StateDirectory.Protect(root);
var config = AgentConfiguration.Load(root);
if (args.Contains("--enroll"))
{
    await EnrollmentClient.Enroll(config, root);
    return;
}
if (config.DeviceId is null)
{
    // Installed from the onboarding page: enroll in the background, then restart as the normal agent.
    var onboarding = Host.CreateApplicationBuilder(args);
    onboarding.Services.AddWindowsService(o => o.ServiceName = "LocalNetworkPolicyAgent");
    onboarding.Logging.AddEventLog(o => o.SourceName = "LocalNetworkPolicyAgent");
    onboarding.Services.AddHostedService(sp => new OnboardingWorker(config, root, sp.GetRequiredService<IHostApplicationLifetime>(),
        sp.GetRequiredService<ILogger<OnboardingWorker>>()));
    await onboarding.Build().RunAsync();
    return;
}
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "LocalNetworkPolicyAgent");
builder.Logging.AddEventLog(o => o.SourceName = "LocalNetworkPolicyAgent");
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(new LocalState(root));
builder.Services.AddSingleton<AgentTransport>();
builder.Services.AddHostedService<PolicyWorker>();
builder.Services.AddHostedService<Lantern.Enrollment.IdentityPipeService>();
await builder.Build().RunAsync();
