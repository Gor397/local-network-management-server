using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace Lantern.Service;

public sealed record ProcessResult(int ExitCode, string Output, string Error);
public static class PowerShell
{
    /// <summary>
    /// Runs one script shipped with the agent. Every bundled script is also embedded in this executable at build time.
    /// An unchanged script (unsigned build) runs with Bypass; a script carrying an Authenticode block (signed build)
    /// runs with AllSigned so PowerShell verifies it; anything else was modified after installation and is refused.
    /// </summary>
    public static Task<ProcessResult> Run(string relativeScript, string[] arguments, CancellationToken token = default)
    {
        string script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, relativeScript));
        if (!script.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) || !File.Exists(script))
            throw new InvalidDataException("Only bundled scripts may run as policy operations.");
        string policy = ExecutionPolicy(relativeScript, File.ReadAllBytes(script));
        return RunProcess(Executable(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", policy, "-File", script, .. arguments], token);
    }

    internal static string ExecutionPolicy(string relativeScript, byte[] onDisk)
    {
        byte[]? shipped = Embedded(relativeScript);
        if (shipped is not null && shipped.AsSpan().SequenceEqual(onDisk)) return "Bypass";
        if (Encoding.UTF8.GetString(onDisk).Contains("# SIG # Begin signature block", StringComparison.Ordinal)) return "AllSigned";
        throw new InvalidDataException("Bundled script was modified after installation.");
    }

    static byte[]? Embedded(string relativeScript)
    {
        string name = "suro-script:" + relativeScript.Replace('\\', '/').TrimStart('/');
        var assembly = Assembly.GetExecutingAssembly();
        // Resource names keep the build host's separator; compare them normalized.
        string? match = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => string.Equals(n.Replace('\\', '/'), name, StringComparison.OrdinalIgnoreCase));
        if (match is null) return null;
        using var stream = assembly.GetManifestResourceStream(match)!;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>The native-architecture Windows PowerShell, also from a 32-bit process on 64-bit Windows.</summary>
    static string Executable()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string folder = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative" : "System32";
        return Path.Combine(windows, folder, "WindowsPowerShell", "v1.0", "powershell.exe");
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
