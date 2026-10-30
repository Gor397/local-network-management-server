using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Suro.Identity;

static class Program
{
    [STAThread]static void Main()
    {
        ApplicationConfiguration.Initialize();
        try
        {
            var status=Pipe.Request(new{operation="status"}).GetAwaiter().GetResult();
            if(status.GetProperty("submitted").GetBoolean())return;
            Application.Run(new IdentityForm());
        }
        catch(Exception){/* Service may not yet be available; the next user logon retries. */}
    }
}
static class Pipe
{
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeServerProcessId(IntPtr handle,out uint pid);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatus status,int size,out int needed);
    [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)]struct ServiceStatus {public uint Type,State,Accepted,Win32Exit,ServiceExit,Checkpoint,WaitHint,ProcessId,Flags;}
    static bool IsAgentService(uint pid)
    {
        // Read-only SCM queries are available to ordinary interactive users. Token queries
        // against a SYSTEM process are deliberately avoided because they can require elevation.
        IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)return false;
        try
        {
            IntPtr service=OpenService(manager,"LocalNetworkPolicyAgent",4);if(service==IntPtr.Zero)return false;
            try{return QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<ServiceStatus>(),out _) && status.State==4 && status.ProcessId==pid;}
            finally{CloseServiceHandle(service);}
        }finally{CloseServiceHandle(manager);}
    }
    public static async Task<JsonElement> Request(object request)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pipe=new NamedPipeClientStream(".","Suro.Identity.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(timeout.Token);
        if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out var pid))throw new IOException("Unverified identity service");
        if(!IsAgentService(pid))throw new IOException("Unverified identity service process");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(request);await pipe.WriteAsync(BitConverter.GetBytes(bytes.Length),timeout.Token);await pipe.WriteAsync(bytes,timeout.Token);await pipe.FlushAsync(timeout.Token);
        byte[] header=new byte[4];await pipe.ReadExactlyAsync(header,timeout.Token);int count=BitConverter.ToInt32(header);
        if(count<2||count>8192)throw new IOException("Invalid service response");
        byte[] reply=new byte[count];await pipe.ReadExactlyAsync(reply,timeout.Token);using var json=JsonDocument.Parse(reply);return json.RootElement.Clone();
    }
}
sealed class IdentityForm:Form
{
    readonly ComboBox language=new(){DropDownStyle=ComboBoxStyle.DropDownList};
    readonly Label explanation=new(){AutoSize=false,Height=90};
    readonly Label nameLabel=new(){AutoSize=true},rankLabel=new(){AutoSize=true};
    readonly TextBox nameInput=new(){MaxLength=256},rankInput=new(){MaxLength=128};
    readonly CheckBox noRank=new(){AutoSize=true};
    readonly Button submit=new(){AutoSize=true};
    Dictionary<string,string> texts=new();
    public IdentityForm()
    {
        Text="Suro";Width=540;Height=430;MinimumSize=new Size(480,400);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(24),ColumnCount=1,RowCount=9,AutoSize=true};
        language.Items.AddRange(["Հայերեն","Русский","English"]);language.SelectedIndex=0;
        foreach(Control control in new Control[]{language,explanation,nameLabel,nameInput,rankLabel,rankInput,noRank,submit}){control.Dock=DockStyle.Top;control.Margin=new Padding(0,4,0,8);layout.Controls.Add(control);}
        Controls.Add(layout);language.SelectedIndexChanged+=(_,_)=>Translate();noRank.CheckedChanged+=(_,_)=>rankInput.Enabled=!noRank.Checked;
        submit.Click+=async(_,_)=>{if(nameInput.Text.Trim().Length<2){MessageBox.Show(texts["name_required"],"Suro");return;}submit.Enabled=false;try{await Pipe.Request(new{operation="submit",full_name=nameInput.Text,military_rank=rankInput.Text,no_military_rank=noRank.Checked});MessageBox.Show(texts["saved"],"Suro");Close();}catch(Exception){MessageBox.Show(texts["error"],"Suro");submit.Enabled=true;}};
        Translate();
    }
    void Translate()
    {
        string code=new[]{"hy","ru","en"}[Math.Max(0,language.SelectedIndex)];
        texts=JsonSerializer.Deserialize<Dictionary<string,string>>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"locales",code+".json")))!;
        explanation.Text=texts["explanation"];nameLabel.Text=texts["full_name"];rankLabel.Text=texts["rank"];noRank.Text=texts["no_rank"];submit.Text=texts["submit"];
    }
}
