using System.Security.Cryptography;
using System.Text.Json;

namespace Lantern.PolicyEngine;

public static class SignedDocument
{
    public static DateTime UtcInstant(string value)=>DateTimeOffset.Parse(value,System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal|System.Globalization.DateTimeStyles.AdjustToUniversal).UtcDateTime;
    public static JsonDocument Verify(string envelopeJson, string publicKey)
    {
        using var envelope = JsonDocument.Parse(envelopeJson);
        if (envelope.RootElement.GetProperty("algorithm").GetString() != "RS256") throw new CryptographicException("Unsupported signature.");
        byte[] payload = Convert.FromBase64String(envelope.RootElement.GetProperty("payload").GetString()!);
        byte[] signature = Convert.FromBase64String(envelope.RootElement.GetProperty("signature").GetString()!);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);
        if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw new CryptographicException("Invalid signed document.");
        return JsonDocument.Parse(payload);
    }

    public static void ValidatePolicy(JsonElement envelope, string deviceId)
    {
        string[] allowed = ["schema_version", "admin_account", "user_account", "require_d", "hide_c", "approved_admins", "firewall_allowances", "mandatory_checks", "weights", "heartbeat_seconds", "heartbeat_deadline_seconds", "evidence_ttl_seconds", "quarantine_on_failure", "quarantine_on_missing_heartbeat", "remediation_grace_seconds", "auto_remediate",
            // Sent only to agents that report the matching feature (backend/app/policies/catalog.py AGENT_FEATURE_KEYS).
            "min_d_gb", "ip_mode", "ip_prefix", "ip_gateway", "dns_servers", "static_ip_address"];
        if (envelope.GetProperty("schema_version").GetInt32() != 1 || envelope.GetProperty("device_id").GetString() != deviceId)
            throw new InvalidDataException("Policy identity or schema mismatch.");
        if (UtcInstant(envelope.GetProperty("valid_until").GetString()!) < DateTime.UtcNow)
            throw new InvalidDataException("Policy has expired.");
        var policy = envelope.GetProperty("document");
        if (policy.GetProperty("schema_version").GetInt32() != 1 || policy.EnumerateObject().Any(p => !allowed.Contains(p.Name)))
            throw new InvalidDataException("Unsupported policy controls.");
        foreach (string key in new[] { "admin_account", "user_account" })
            if (!System.Text.RegularExpressions.Regex.IsMatch(policy.GetProperty(key).GetString()!, "^[A-Za-z][A-Za-z0-9_-]{0,19}$"))
                throw new InvalidDataException("Unsafe account name.");
    }
}
