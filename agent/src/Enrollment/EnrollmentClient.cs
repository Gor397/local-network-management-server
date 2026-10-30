using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using Lantern.Security;

namespace Lantern.Enrollment;

public static class EnrollmentClient
{
    public static async Task Enroll(AgentConfiguration config, string root, CancellationToken cancel = default)
    {
        // Provisioning file is protected by installer ACLs, never command-line token arguments.
        var tokenFile = Path.Combine(root, "enrollment.token");
        var cngName = "Lantern-Device-Identity";
        using var key = CngKey.Exists(cngName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey)
            ? CngKey.Open(cngName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey)
            : CngKey.Create(CngAlgorithm.Rsa, cngName, new CngKeyCreationParameters {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider, KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                ExportPolicy = CngExportPolicies.None, Parameters = { new CngProperty("Length", BitConverter.GetBytes(3072), CngPropertyOptions.None) } });
        using var rsa = new RSACng(key);
        string csrPath = Path.Combine(root, "enrollment.csr");
        // Persist CSR for retry: RSA-PSS CSR signatures may otherwise change between retries.
        string csr;
        if (File.Exists(csrPath)) csr = await File.ReadAllTextAsync(csrPath);
        else
        {
            var request = new CertificateRequest("CN=Pending Suro Device", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            csr = request.CreateSigningRequestPem();
            await File.WriteAllTextAsync(csrPath, csr);
        }
        using var http = new HttpClient(Tls.Handler(config)) { Timeout = TimeSpan.FromSeconds(20) };
        if (!File.Exists(tokenFile))
            config = await RequestOnboarding(http, config, root, csr, tokenFile, cancel);
        var token = (await File.ReadAllTextAsync(tokenFile, cancel)).Trim();
        while (true)
        {
            using var response = await http.PostAsync(config.Server.TrimEnd('/') + "/api/v1/agent/enroll",
                new StringContent(JsonSerializer.Serialize(new { token, csr, primary_mac = config.PrimaryMac }), Encoding.UTF8, "application/json"));
            response.EnsureSuccessStatusCode();
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                Console.WriteLine(config.UiLanguage == "ru" ? "Запрос сертификата ожидает подтверждения администратора." : config.UiLanguage == "en" ? "Certificate request is awaiting administrator approval." : "Վկայագրի հարցումը սպասում է ադմինիստրատորի հաստատմանը։");
                await Task.Delay(TimeSpan.FromSeconds(10), cancel);
                continue;
            }
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            using var certificate = X509Certificate2.CreateFromPem(document.RootElement.GetProperty("certificate").GetString()!);
            using var identity = certificate.CopyWithPrivateKey(rsa);
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(identity);
            var saved = config with { DeviceId = document.RootElement.GetProperty("device_id").GetString(), CertificateThumbprint = identity.Thumbprint };
            await File.WriteAllTextAsync(Path.Combine(root, "config.json"), JsonSerializer.Serialize(saved, Json.Options));
            File.Delete(tokenFile);
            Console.WriteLine(config.UiLanguage == "ru" ? "Устройство зарегистрировано в Suro. Запустите LocalNetworkPolicyAgent." : config.UiLanguage == "en" ? "Device enrolled in Suro. Start LocalNetworkPolicyAgent." : "Սարքը գրանցվել է Suro-ում։ Գործարկեք LocalNetworkPolicyAgent ծառայությունը։");
            return;
        }
    }

    /// <summary>
    /// Portal install: ask the server to accept this computer's CSR. The server answers with a token only while an
    /// administrator has opened onboarding for one of these MACs, and an administrator still approves the request.
    /// </summary>
    static async Task<AgentConfiguration> RequestOnboarding(HttpClient http, AgentConfiguration config, string root, string csr,
        string tokenFile, CancellationToken cancel)
    {
        var macs = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType is System.Net.NetworkInformation.NetworkInterfaceType.Ethernet
                                                 or System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211)
            .Select(n => n.GetPhysicalAddress().ToString()).Where(m => m.Length == 12).Distinct().Take(16).ToArray();
        while (true)
        {
            try
            {
                using var response = await http.PostAsync(config.Server.TrimEnd('/') + "/api/v1/agent/onboarding-request",
                    new StringContent(JsonSerializer.Serialize(new { csr, macs, hostname = Environment.MachineName }), Encoding.UTF8, "application/json"), cancel);
                response.EnsureSuccessStatusCode();
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancel));
                if (document.RootElement.TryGetProperty("token", out var token) && token.ValueKind == JsonValueKind.String)
                {
                    config = config with { PrimaryMac = document.RootElement.GetProperty("primary_mac").GetString()! };
                    await File.WriteAllTextAsync(Path.Combine(root, "config.json"), JsonSerializer.Serialize(config, Json.Options), cancel);
                    await File.WriteAllTextAsync(tokenFile, token.GetString(), cancel);
                    return config;
                }
            }
            catch (HttpRequestException) { /* Server unreachable on the onboarding network: retry quietly. */ }
            // Not (yet) allowed: the administrator may open onboarding later. Retry slowly to keep the server idle.
            await Task.Delay(TimeSpan.FromMinutes(1), cancel);
        }
    }
}
