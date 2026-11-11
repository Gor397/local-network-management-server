using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace Suro.Setup
{
    sealed class SetupException : Exception
    {
        public int Code { get; }
        public SetupException(int code, string message) : base(message) { Code = code; }
    }

    enum Outcome { Installed, Updated }

    /// <summary>
    /// Installs or updates the Suro Client: protected state folder, program files, Windows service, sign-in entry
    /// for the identity window and an uninstall entry. The device identity in %ProgramData%\Lantern is always kept.
    /// </summary>
    sealed class Installer
    {
        public const string ServiceName = "LocalNetworkPolicyAgent";
        const string TrailerMagic = "SUROCFG1";
        const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SuroClient";
        // Same service permissions as the MSI: only SYSTEM and Administrators may change or stop it.
        const string ServiceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)";
        static readonly string[] SiteKeys = { "server", "signing_public_key", "agent_publisher_thumbprint", "server_certificate_sha256", "ui_language" };
        static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        static readonly SecurityIdentifier AdministratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        static readonly SecurityIdentifier UsersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

        public static readonly string InstallDirectory =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Lantern Policy Agent");
        public static readonly string StateDirectory =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Lantern");

        public string Language { get; private set; } = "hy";
        string? site;

        public static string Version => Assembly.GetExecutingAssembly().GetName().Version.ToString(3);

        /// <summary>Reads settings and language before any window is shown; never changes the computer.</summary>
        public void Prepare()
        {
            site = ReadTrailer() ?? ReadEmbedded("site.json");
            string? language = null;
            if (site != null) language = Validate(site);
            string config = Path.Combine(StateDirectory, "config.json");
            if (language == null && File.Exists(config))
            {
                try { language = Parse(File.ReadAllText(config, Encoding.UTF8)).TryGetValue("ui_language", out var value) ? value as string : null; }
                catch (Exception) { language = null; }
            }
            if (language == "hy" || language == "ru" || language == "en") Language = language;
        }

        public Outcome Run(Action<string> step)
        {
            Log("Suro setup " + Version + " started");
            Version os = Environment.OSVersion.Version;
            if (os.Major < 10 || os.Build < 14393)
                throw new SetupException(2, "Windows 10 version 1607 or later is required (found " + os + ").");
            string architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            using (Stream? payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload-" + architecture + ".zip"))
            {
                if (payload == null)
                    throw new SetupException(3, "This setup does not contain the " + (architecture == "x64" ? "64-bit" : "32-bit") + " Suro Client.");
                ProtectState();
                bool enrolled = File.Exists(Path.Combine(StateDirectory, "config.json"));
                if (site == null && !enrolled)
                    throw new SetupException(1, "This setup has no server settings. Download it again from the Suro page of your network.");

                step("stop");
                StopClient();
                step("copy");
                Directory.CreateDirectory(InstallDirectory);
                ProtectInstallDirectory();
                Extract(payload);
                if (site != null) File.WriteAllText(Path.Combine(InstallDirectory, "site.json"), site, new UTF8Encoding(false));
                WriteInstallManifest();
                step("service");
                RegisterService();
                RegisterStartup();
                step("start");
                StartService();
                Log("Finished: " + (enrolled ? "updated" : "installed") + " (" + architecture + ")");
                return enrolled ? Outcome.Updated : Outcome.Installed;
            }
        }

        // ---- settings ----------------------------------------------------------------------------------------

        /// <summary>The Suro server appends its settings to the downloaded file: JSON, 4-byte length, magic.</summary>
        static string? ReadTrailer()
        {
            string path = Assembly.GetExecutingAssembly().Location;
            using (var file = File.OpenRead(path))
            {
                if (file.Length < 12) return null;
                var tail = new byte[12];
                file.Seek(-12, SeekOrigin.End);
                ReadExactly(file, tail);
                if (Encoding.ASCII.GetString(tail, 4, 8) != TrailerMagic) return null;
                int length = BitConverter.ToInt32(tail, 0);
                if (length <= 0 || length > 64 * 1024 || length > file.Length - 12) return null;
                var json = new byte[length];
                file.Seek(-12 - length, SeekOrigin.End);
                ReadExactly(file, json);
                return new UTF8Encoding(false, true).GetString(json);
            }
        }

        static void ReadExactly(Stream stream, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = stream.Read(buffer, offset, buffer.Length - offset);
                if (read <= 0) throw new EndOfStreamException();
                offset += read;
            }
        }

        static string? ReadEmbedded(string name)
        {
            using (Stream? stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (stream == null) return null;
                using (var reader = new StreamReader(stream, new UTF8Encoding(false, true))) return reader.ReadToEnd();
            }
        }

        static Dictionary<string, object> Parse(string json) =>
            new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json) ?? new Dictionary<string, object>();

        /// <summary>Same rules as the agent and the MSI build: HTTPS server, a public key, no other fields (never a token).</summary>
        static string? Validate(string json)
        {
            Dictionary<string, object> values;
            try { values = Parse(json); }
            catch (Exception) { throw new SetupException(4, "The server settings in this setup are damaged."); }
            var extra = values.Keys.Where(k => !SiteKeys.Contains(k)).ToList();
            if (extra.Count > 0) throw new SetupException(4, "Unexpected server settings: " + string.Join(", ", extra));
            if (!(values.TryGetValue("server", out var server) && server is string url &&
                  Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == "https"))
                throw new SetupException(4, "The server address must use HTTPS.");
            if (!(values.TryGetValue("signing_public_key", out var key) && key is string pem && pem.Contains("BEGIN PUBLIC KEY")))
                throw new SetupException(4, "The server policy signing key is missing.");
            return values.TryGetValue("ui_language", out var language) ? language as string : null;
        }

        // ---- files and permissions -----------------------------------------------------------------------------

        /// <summary>Mirrors Lantern.Security.StateDirectory: SYSTEM/Administrators only; refuses state planted by a user.</summary>
        static void ProtectState()
        {
            var directory = Directory.CreateDirectory(StateDirectory);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { SystemSid, AdministratorsSid })
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.SetOwner(AdministratorsSid);
            directory.SetAccessControl(acl);
            foreach (var name in new[] { "config.json", "enrollment.token", "enrollment.csr" })
            {
                var file = new FileInfo(Path.Combine(StateDirectory, name));
                if (!file.Exists) continue;
                var owner = file.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
                if (owner == null || !(owner.Equals(SystemSid) || owner.Equals(AdministratorsSid)))
                    throw new SetupException(5, name + " in " + StateDirectory + " was not created by Windows or an administrator.");
            }
        }

        static void ProtectInstallDirectory()
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            acl.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            // Standard users may run the identity window, nothing more.
            acl.AddAccessRule(new FileSystemAccessRule(UsersSid, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.SetOwner(AdministratorsSid);
            new DirectoryInfo(InstallDirectory).SetAccessControl(acl);
        }

        static void Extract(Stream payload)
        {
            string root = Path.GetFullPath(InstallDirectory).TrimEnd('\\') + "\\";
            using (var archive = new ZipArchive(payload, ZipArchiveMode.Read))
            {
                foreach (var entry in archive.Entries)
                {
                    string target = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('/', '\\')));
                    if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                        throw new SetupException(6, "Unsafe path in payload: " + entry.FullName);
                    if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) { Directory.CreateDirectory(target); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    for (int attempt = 1; ; attempt++)
                    {
                        try { entry.ExtractToFile(target, true); break; }
                        catch (IOException) when (attempt < 10) { System.Threading.Thread.Sleep(1000); }
                        catch (UnauthorizedAccessException) when (attempt < 10) { System.Threading.Thread.Sleep(1000); }
                    }
                }
            }
        }

        /// <summary>
        /// SHA-256 of the client's own code and scripts, kept where only SYSTEM/Administrators can write. Unsigned builds
        /// use it as the agent.integrity_valid evidence (Monitoring/Inspect.ps1); it detects changes after installation.
        /// </summary>
        static void WriteInstallManifest()
        {
            var files = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string root = Path.GetFullPath(InstallDirectory).TrimEnd('\\') + "\\";
            var candidates = Directory.GetFiles(root, "*.ps1", SearchOption.AllDirectories)
                .Concat(new[] { "NetworkPolicyClient.exe", "NetworkPolicyClient.dll", "SuroIdentity.exe", "SuroIdentity.dll" }
                    .Select(name => Path.Combine(root, name)).Where(File.Exists));
            using (var sha = SHA256.Create())
            {
                foreach (string path in candidates)
                    using (var stream = File.OpenRead(path))
                        files[path.Substring(root.Length)] = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
            }
            var manifest = new Dictionary<string, object> { ["version"] = Version, ["written_at"] = DateTime.UtcNow.ToString("o"), ["files"] = files };
            string target = Path.Combine(StateDirectory, "install-manifest.json");
            File.WriteAllText(target + ".tmp", new JavaScriptSerializer().Serialize(manifest), new UTF8Encoding(false));
            if (File.Exists(target)) File.Replace(target + ".tmp", target, null);
            else File.Move(target + ".tmp", target);
        }

        // ---- service and start-up entries ----------------------------------------------------------------------

        static bool ServiceExists() => ServiceController.GetServices().Any(s => s.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));

        static void StopClient()
        {
            if (ServiceExists())
            {
                using (var service = new ServiceController(ServiceName))
                {
                    if (service.Status != ServiceControllerStatus.Stopped)
                    {
                        Log("Stopping service");
                        if (service.Status != ServiceControllerStatus.StopPending) service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(90));
                    }
                }
            }
            // Identity windows run in users' sessions; they reopen at the next sign-in.
            string root = Path.GetFullPath(InstallDirectory);
            foreach (var process in Process.GetProcessesByName("SuroIdentity").Concat(Process.GetProcessesByName("NetworkPolicyClient")))
            {
                try
                {
                    if (process.MainModule.FileName.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { process.Kill(); process.WaitForExit(10000); }
                }
                catch (Exception exception) { Log("Could not stop " + process.ProcessName + ": " + exception.GetType().Name); }
                finally { process.Dispose(); }
            }
        }

        static void RegisterService()
        {
            string binary = "\"\\\"" + Path.Combine(InstallDirectory, "NetworkPolicyClient.exe") + "\\\"\"";
            if (ServiceExists()) Sc("config " + ServiceName + " binPath= " + binary + " start= auto");
            else Sc("create " + ServiceName + " binPath= " + binary + " start= auto obj= LocalSystem DisplayName= \"Suro Network Policy Agent\"");
            Sc("description " + ServiceName + " \"Audits and reconciles approved local network policies.\"");
            Sc("sdset " + ServiceName + " " + ServiceSddl);
            Sc("failure " + ServiceName + " reset= 86400 actions= restart/60000/restart/120000/restart/300000");
        }

        static void Sc(string arguments)
        {
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var process = Process.Start(start)!)
            {
                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                    throw new SetupException(7, "sc.exe " + arguments.Split(' ')[0] + " failed (" + process.ExitCode + "): " + output.Trim());
            }
        }

        static RegistryKey Machine() =>
            RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);

        static void RegisterStartup()
        {
            using (var machine = Machine())
            {
                using (var run = machine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                    run.SetValue("SuroIdentification", "\"" + Path.Combine(InstallDirectory, "SuroIdentity.exe") + "\"", RegistryValueKind.String);
                using (var entry = machine.CreateSubKey(UninstallKey))
                {
                    string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                    entry.SetValue("DisplayName", "Suro Client");
                    entry.SetValue("DisplayVersion", Version);
                    entry.SetValue("Publisher", "Suro Project");
                    entry.SetValue("InstallLocation", InstallDirectory);
                    entry.SetValue("DisplayIcon", Path.Combine(InstallDirectory, "SuroIdentity.exe"));
                    entry.SetValue("UninstallString", "\"" + powershell + "\" -NoProfile -ExecutionPolicy Bypass -File \"" +
                                                      Path.Combine(InstallDirectory, @"Setup\Uninstall-Suro.ps1") + "\"");
                    entry.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    entry.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                }
            }
        }

        static void StartService()
        {
            using (var service = new ServiceController(ServiceName))
            {
                service.Refresh();
                if (service.Status == ServiceControllerStatus.Running) return;
                service.Start();
                try { service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60)); }
                catch (System.ServiceProcess.TimeoutException)
                {
                    throw new SetupException(8, "The Suro service did not start. See Windows Event Viewer > Application > LocalNetworkPolicyAgent.");
                }
            }
        }

        // ---- log -----------------------------------------------------------------------------------------------

        public static void Log(string message)
        {
            try
            {
                Directory.CreateDirectory(StateDirectory);
                string path = Path.Combine(StateDirectory, "setup.log");
                if (File.Exists(path) && new FileInfo(path).Length > 1024 * 1024) File.Delete(path);
                File.AppendAllText(path, DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine, new UTF8Encoding(false));
            }
            catch (Exception) { }
        }
    }
}
