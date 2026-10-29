using System.Text.Json;

namespace Lantern.Security;

public sealed record AgentConfiguration(string Server, string PrimaryMac, string SigningPublicKey,
    string? DeviceId = null, string? CertificateThumbprint = null, int PollSeconds = 120,
    string? AgentPublisherThumbprint = null)
{
    public static AgentConfiguration Load(string root)
    {
        var config = JsonSerializer.Deserialize<AgentConfiguration>(File.ReadAllText(Path.Combine(root, "config.json")), Json.Options)
                     ?? throw new InvalidDataException("Missing configuration.");
        if (!Uri.TryCreate(config.Server, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length > 0 || uri.Query.Length > 0)
            throw new InvalidDataException("A verified HTTPS server is required.");
        if (config.PollSeconds < 30) throw new InvalidDataException("Polling interval is too short.");
        return config;
    }
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true, WriteIndented = true };
}
