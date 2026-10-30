using System.Text.Json;

namespace Lantern.Security;

public sealed record AgentConfiguration(string Server, string PrimaryMac, string SigningPublicKey,
    string? DeviceId = null, string? CertificateThumbprint = null, int PollSeconds = 120,
    string? AgentPublisherThumbprint = null, string UiLanguage = "hy", string? ServerCertificateSha256 = null)
{
    public static AgentConfiguration Load(string root)
    {
        var path = Path.Combine(root, "config.json");
        // A portal-installed client starts from the site file the signed MSI carries (no secrets, no token).
        var site = Path.Combine(AppContext.BaseDirectory, "site.json");
        if (!File.Exists(path) && File.Exists(site)) File.Copy(site, path);
        var config = JsonSerializer.Deserialize<AgentConfiguration>(File.ReadAllText(path), Json.Options)
                     ?? throw new InvalidDataException("Missing configuration.");
        if (!Uri.TryCreate(config.Server, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length > 0 || uri.Query.Length > 0)
            throw new InvalidDataException("A verified HTTPS server is required.");
        if (config.PollSeconds < 30) throw new InvalidDataException("Polling interval is too short.");
        return config;
    }
}

public static class Tls
{
    /// <summary>Windows trust, or the exact server certificate pinned in the site configuration (no public CA offline).</summary>
    public static HttpClientHandler Handler(AgentConfiguration config)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (!string.IsNullOrWhiteSpace(config.ServerCertificateSha256))
        {
            var pin = config.ServerCertificateSha256.Replace(":", "").Trim().ToLowerInvariant();
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None ||
                (certificate is not null && (errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
                 Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(certificate.RawData)).ToLowerInvariant() == pin);
        }
        return handler;
    }
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true, WriteIndented = true };
}
