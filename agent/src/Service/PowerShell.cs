using System.Diagnostics;
using System.Text;

namespace Lantern.Service;

public sealed record ProcessResult(int ExitCode, string Output, string Error);
public static class PowerShell
{
    public static Task<ProcessResult> Run(string relativeScript, string[] arguments, CancellationToken token = default)
    {
        string script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, relativeScript));
        if (!script.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) || !File.Exists(script))
            throw new InvalidDataException("Only bundled scripts may run as policy operations.");
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        return RunProcess(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", script, .. arguments], token);
    }
    public static async Task<ProcessResult> RunProcess(string executable, string[] arguments, CancellationToken token = default)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException("Process did not start.");
        // Drain streams continuously while bounding memory; do not buffer installer logs indefinitely.
        async Task<string> Drain(StreamReader reader)
        {
            var tail = new StringBuilder(); char[] buffer = new char[4096]; int read;
            while ((read = await reader.ReadAsync(buffer.AsMemory(), token)) > 0)
            { tail.Append(buffer, 0, read); if (tail.Length > 1024 * 1024) tail.Remove(0, tail.Length - 1024 * 1024); }
            return tail.ToString();
        }
        var output = Drain(process.StandardOutput); var error = Drain(process.StandardError);
        await process.WaitForExitAsync(token);
        return new ProcessResult(process.ExitCode, await output, await error);
    }
}
