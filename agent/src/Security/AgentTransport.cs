using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Lantern.Security;

public sealed class AgentTransport : IDisposable
{
    readonly HttpClient client;
    readonly X509Certificate2 certificate;
    readonly RSA privateKey;
    readonly string fingerprint;
    readonly object signingLock = new();

    public AgentTransport(AgentConfiguration config)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        certificate = store.Certificates.Find(X509FindType.FindByThumbprint, config.CertificateThumbprint ?? throw new InvalidDataException("Device is not enrolled."), false)
                          .OfType<X509Certificate2>().Single(c => c.HasPrivateKey);
        privateKey = certificate.GetRSAPrivateKey() ?? throw new CryptographicException("RSA device key missing.");
        fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();
        client = new HttpClient(Tls.Handler(config))
        { BaseAddress = new Uri(config.Server.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(45) };
    }

    public async Task<HttpResponseMessage> Send(HttpMethod method, string path, object? body = null,
        Dictionary<string,string>? headers = null, bool streaming = false, CancellationToken cancellationToken = default)
    {
        byte[] bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, Json.Options);
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        string target = "/" + path.TrimStart('/');
        string message = $"{method.Method}\n{target}\n{timestamp}\n{nonce}\n{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}";
        using var request = new HttpRequestMessage(method, path.TrimStart('/'));
        request.Headers.Add("X-Device-Certificate", fingerprint);
        request.Headers.Add("X-Device-Time", timestamp);
        request.Headers.Add("X-Device-Nonce", nonce);
        byte[] signature;
        lock(signingLock) signature=privateKey.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.Headers.Add("X-Device-Signature", Convert.ToBase64String(signature));
        if (bytes.Length > 0)
        {
            request.Content = new ByteArrayContent(bytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        if (headers is not null) foreach (var pair in headers) request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        return await client.SendAsync(request, streaming ? HttpCompletionOption.ResponseHeadersRead : HttpCompletionOption.ResponseContentRead, cancellationToken);
    }

    public void Dispose() { privateKey.Dispose(); certificate.Dispose(); client.Dispose(); }
}
