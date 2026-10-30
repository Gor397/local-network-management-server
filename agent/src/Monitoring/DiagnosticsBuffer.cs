using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Diagnostics.Eventing.Reader;
using Lantern.Security;

namespace Lantern.Monitoring;

public sealed class DiagnosticsBuffer(LocalState state, AgentTransport transport)
{
    public async Task Capture(bool? reachable, CancellationToken token)
    {
        var sample = new Dictionary<string,object?> { ["sequence"] = Guid.NewGuid().ToString("N"),
            ["observed_at"] = DateTimeOffset.UtcNow, ["management_reachable"] = reachable, ["connection_state"] = "UNKNOWN" };
        try
        {
            var wifi = Wireless.Snapshot();
            foreach (var pair in wifi) sample[pair.Key] = pair.Value;
            var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.NetworkInterfaceType==NetworkInterfaceType.Wireless80211 && n.OperationalStatus==OperationalStatus.Up);
            var properties = adapter?.GetIPProperties();
            sample["ip_addresses"] = properties?.UnicastAddresses.Select(a=>a.Address.ToString()).Take(16).ToArray() ?? [];
            sample["gateways"] = properties?.GatewayAddresses.Select(a=>a.Address.ToString()).Take(8).ToArray() ?? [];
            sample["dns"] = properties?.DnsAddresses.Select(a=>a.ToString()).Take(8).ToArray() ?? [];
            var events = new List<object>();
            using var reader = new EventLogReader(new EventLogQuery("Microsoft-Windows-WLAN-AutoConfig/Operational",PathType.LogName,"*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]") { ReverseDirection=true });
            for (int i=0;i<10;i++)
            {
                using var entry=reader.ReadEvent(); if(entry is null) break;
                events.Add(new {event_id=entry.Id,record_id=entry.RecordId,at=entry.TimeCreated?.ToUniversalTime()});
            }
            sample["events"]=events;
        }
        catch (Exception e) when(e is not OperationCanceledException) { /* Unavailable WLAN data remains unknown. */ }
        var existing=await Read(token);
        existing.Add(JsonSerializer.SerializeToElement(sample,Json.Options));
        // Bounded metadata only: no passwords, browsing history, files or full event messages.
        var bounded=existing.TakeLast(120).ToList();
        await state.Save("diagnostics-buffer.json",JsonSerializer.Serialize(bounded,Json.Options));
    }

    async Task<List<JsonElement>> Read(CancellationToken token)
    {
        if(!File.Exists(state.PathFor("diagnostics-buffer.json")))return [];
        var info=new FileInfo(state.PathFor("diagnostics-buffer.json"));
        if(info.Length>1024*1024)throw new InvalidDataException("Diagnostic buffer size limit exceeded.");
        return JsonSerializer.Deserialize<List<JsonElement>>(await File.ReadAllTextAsync(info.FullName,token),Json.Options) ?? [];
    }
    public async Task Flush(CancellationToken token)
    {
        var rows=await Read(token);if(rows.Count==0)return;
        using var response=await transport.Send(HttpMethod.Post,"api/v1/agent/diagnostics",new {observations=rows.Take(100)},cancellationToken:token);
        if(!response.IsSuccessStatusCode)return;
        using var document=JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
        var accepted=document.RootElement.GetProperty("accepted").EnumerateArray().Select(s=>s.GetString()).ToHashSet();
        var remaining=rows.Where(r=>!accepted.Contains(r.GetProperty("sequence").GetString())).ToArray();
        await state.Save("diagnostics-buffer.json",JsonSerializer.Serialize(remaining,Json.Options));
    }
}

internal static class Wireless
{
    [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
    [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
    [DllImport("wlanapi.dll")] static extern uint WlanEnumInterfaces(IntPtr handle,IntPtr reserved,out IntPtr list);
    [DllImport("wlanapi.dll")] static extern uint WlanQueryInterface(IntPtr handle,ref Guid id,uint opcode,IntPtr reserved,out int size,out IntPtr data,out int type);
    [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr memory);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Interface {public Guid Id;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Description;public int State;}
    [StructLayout(LayoutKind.Sequential)] struct Ssid {public uint Length;[MarshalAs(UnmanagedType.ByValArray,SizeConst=32)]public byte[] Bytes;}
    [StructLayout(LayoutKind.Sequential)] struct Association {public Ssid Ssid;public int BssType;[MarshalAs(UnmanagedType.ByValArray,SizeConst=6)]public byte[] Bssid;public int Phy;public uint PhyIndex;public uint Signal;public uint Rx;public uint Tx;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Connection {public int State;public int Mode;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Profile;public Association Association;}
    public static Dictionary<string,object?> Snapshot()
    {
        var result=new Dictionary<string,object?>();
        if(WlanOpenHandle(2,IntPtr.Zero,out _,out var handle)!=0)return result;
        try
        {
            if(WlanEnumInterfaces(handle,IntPtr.Zero,out var list)!=0)return result;
            try
            {
                var count=Marshal.ReadInt32(list);int length=Marshal.SizeOf<Interface>();
                for(int i=0;i<Math.Min(count,16);i++)
                {
                    var item=Marshal.PtrToStructure<Interface>(list+8+i*length);
                    if(item.State!=1)continue;
                    if(WlanQueryInterface(handle,ref item.Id,7,IntPtr.Zero,out _,out var data,out _)!=0)continue;
                    try
                    {
                        var connection=Marshal.PtrToStructure<Connection>(data);var a=connection.Association;
                        result["ssid"]=Encoding.UTF8.GetString(a.Ssid.Bytes,0,(int)Math.Min(32,a.Ssid.Length));
                        result["bssid"]=string.Join(":",a.Bssid.Select(b=>b.ToString("X2")));
                        result["signal_quality"]=(int)a.Signal;result["connection_state"]="CONNECTED";return result;
                    }finally{WlanFreeMemory(data);}
                }
            }finally{WlanFreeMemory(list);}
        }finally{WlanCloseHandle(handle,IntPtr.Zero);}
        result["connection_state"]="DISCONNECTED";return result;
    }
}
