using System.Diagnostics;
using Lantern.Security;
using Lantern.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Lantern.Enrollment;

/// <summary>Service mode before enrollment: request approval, wait for the certificate, then restart as the agent.</summary>
public sealed class OnboardingWorker(AgentConfiguration config, string root, IHostApplicationLifetime lifetime,
    ILogger<OnboardingWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await EnrollmentClient.Enroll(config, root, stoppingToken);
                // The interactive user's registration window, started in their session (never in Session 0).
                await PowerShell.Run("Enrollment/Start-IdentityUI.ps1", [], stoppingToken);
                // SCM cannot restart a service from inside it; a short detached command starts it again as the agent.
                Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                    "/c ping -n 6 127.0.0.1 >nul & sc.exe start LocalNetworkPolicyAgent") { CreateNoWindow = true, UseShellExecute = false });
                lifetime.StopApplication();
                return;
            }
            catch (OperationCanceledException) { return; }
            catch (Exception exception)
            {
                logger.LogWarning("Onboarding attempt failed: {ErrorType}", exception.GetType().Name);
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }
    }
}
