using System.Security.AccessControl;
using System.Security.Principal;

namespace Lantern.Security;

/// <summary>
/// ProgramData lets standard users create files. A user who planted config.json (rogue server, signing key and
/// publisher) before installation would get code run as SYSTEM, so state must be owned by SYSTEM/Administrators.
/// </summary>
public static class StateDirectory
{
    static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static void Protect(string root)
    {
        var directory = Directory.CreateDirectory(root);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { System, Administrators })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.SetOwner(Administrators);
        directory.SetAccessControl(acl);
        foreach (var name in new[] { "config.json", "enrollment.token", "enrollment.csr" })
        {
            var file = new FileInfo(Path.Combine(root, name));
            if (!file.Exists) continue;
            var owner = file.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            if (owner is null || !(owner.Equals(System) || owner.Equals(Administrators)))
                throw new UnauthorizedAccessException($"{name} was not created by SYSTEM or an administrator; refusing to trust it.");
        }
    }
}
