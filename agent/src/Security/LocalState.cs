using System.Text.Json;
using System.Security.Cryptography;

namespace Lantern.Security;

public sealed class LocalState(string root)
{
    public string Root { get; } = root;
    public string PathFor(string name) => Path.Combine(Root, name);
    public async Task Save(string name, string value)
    {
        var temporary = PathFor(name + ".new");
        await File.WriteAllTextAsync(temporary, value);
        File.Move(temporary, PathFor(name), true);
    }
    public async Task Log(string code, object details)
    {
        var path = PathFor("agent.jsonl");
        if (File.Exists(path) && new FileInfo(path).Length > 2 * 1024 * 1024)
            File.Move(path, PathFor("agent.previous.jsonl"), true);
        await File.AppendAllTextAsync(path, JsonSerializer.Serialize(new { time = DateTimeOffset.UtcNow, code, details }, Json.Options).Replace("\n", "") + "\n");
    }
}
