using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using Lantern.Security;

namespace Lantern.Enrollment;

public static class EnrollmentClient
{
    public static async Task Enroll(AgentConfiguration config, string root)
    {
        // Provisioning file is protected by installer ACLs, never command-line token arguments.
        var tokenFile = Path.Combine(root, "enrollment.token");
        var token = (await File.ReadAllTextAsync(tokenFile)).Trim();
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
            var request = new CertificateRequest("CN=Pending Lantern Device", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            csr = request.CreateSigningRequestPem();
            await File.WriteAllTextAsync(csrPath, csr);
        }
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        while (true)
        {
            using var response = await http.PostAsync(config.Server.TrimEnd('/') + "/api/v1/agent/enroll",
                new StringContent(JsonSerializer.Serialize(new { token, csr, primary_mac = config.PrimaryMac }), Encoding.UTF8, "application/json"));
            response.EnsureSuccessStatusCode();
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                Console.WriteLine("Certificate request is awaiting administrator approval.");
                await Task.Delay(TimeSpan.FromSeconds(10));
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
            Console.WriteLine("Device enrolled. Start LocalNetworkPolicyAgent.");
            return;
        }
    }
}
