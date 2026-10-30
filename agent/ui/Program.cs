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
    readonly Label title=new(){AutoSize=true,Font=new Font("Segoe UI",16,FontStyle.Bold)};
    readonly Label explanation=new(){AutoSize=false,Height=80};
    readonly Label firstLabel=new(){AutoSize=true},lastLabel=new(){AutoSize=true},rankLabel=new(){AutoSize=true};
    readonly TextBox firstInput=new(){MaxLength=128},lastInput=new(){MaxLength=128},rankInput=new(){MaxLength=128};
    readonly Button submit=new(){AutoSize=true,MinimumSize=new Size(0,44)};
    Dictionary<string,string> texts=new();
    public IdentityForm()
    {
        Text="Suro";Width=560;Height=520;MinimumSize=new Size(480,480);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",11);
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(24),ColumnCount=1,RowCount=10,AutoSize=true};
        language.Items.AddRange(["Հայերեն","Русский","English"]);language.SelectedIndex=0;
        foreach(Control control in new Control[]{language,title,explanation,firstLabel,firstInput,lastLabel,lastInput,rankLabel,rankInput,submit}){control.Dock=DockStyle.Top;control.Margin=new Padding(0,4,0,8);layout.Controls.Add(control);}
        Controls.Add(layout);language.SelectedIndexChanged+=(_,_)=>Translate();AcceptButton=submit;
        submit.Click+=async(_,_)=>{
            if(firstInput.Text.Trim().Length<1||lastInput.Text.Trim().Length<1){MessageBox.Show(texts["name_required"],"Suro");(firstInput.Text.Trim().Length<1?firstInput:lastInput).Focus();return;}
            submit.Enabled=false;
            // A blank rank means "no military rank"; the user is not asked twice.
            try{await Pipe.Request(new{operation="submit",first_name=firstInput.Text,last_name=lastInput.Text,military_rank=rankInput.Text,no_military_rank=rankInput.Text.Trim().Length==0});MessageBox.Show(texts["saved"],"Suro");Close();}
            catch(Exception){MessageBox.Show(texts["error"],"Suro");submit.Enabled=true;}};
        Translate();
    }
    void Translate()
    {
        string code=new[]{"hy","ru","en"}[Math.Max(0,language.SelectedIndex)];
        texts=JsonSerializer.Deserialize<Dictionary<string,string>>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"locales",code+".json")))!;
        title.Text=texts["title"];explanation.Text=texts["explanation"];firstLabel.Text=texts["first_name"];lastLabel.Text=texts["last_name"];
        rankLabel.Text=texts["rank"];submit.Text=texts["submit"];
    }
}
