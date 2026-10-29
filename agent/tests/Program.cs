using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lantern.PolicyEngine;

using var key = RSA.Create(3072);
string publicKey = key.ExportSubjectPublicKeyInfoPem();
string Sign(byte[] bytes) => JsonSerializer.Serialize(new {algorithm="RS256",payload=Convert.ToBase64String(bytes),signature=Convert.ToBase64String(key.SignData(bytes,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))});
int passed=0;
void Assert(bool condition,string name){if(!condition)throw new Exception(name);Console.WriteLine("PASS "+name);passed++;}
void Reject(Action action,string name){try{action();}catch(Exception e)when(e is CryptographicException or InvalidDataException){Assert(true,name);return;}throw new Exception("Accepted: "+name);}
byte[] payload=Encoding.UTF8.GetBytes("{\"message\":\"Հայերեն Русский English\"}");
using var valid=SignedDocument.Verify(Sign(payload),publicKey);
Assert(valid.RootElement.GetProperty("message").GetString()!.Contains("Հայերեն"),"UTF-8 signature verification");
string tampered=Sign(payload).Replace(Convert.ToBase64String(payload),Convert.ToBase64String(Encoding.UTF8.GetBytes("{}")));
Reject(()=>SignedDocument.Verify(tampered,publicKey),"Tampered payload rejected");
using var wrong=RSA.Create(3072);
Reject(()=>SignedDocument.Verify(Sign(payload),wrong.ExportSubjectPublicKeyInfoPem()),"Wrong policy key rejected");
var document=new{schema_version=1,device_id="device-a",version_id="v1",revision=1,mode="AUDIT",valid_until=DateTime.UtcNow.AddHours(1).ToString("O"),document=new{schema_version=1,admin_account="admin",user_account="user"}};
using var policy=JsonDocument.Parse(JsonSerializer.Serialize(document));
SignedDocument.ValidatePolicy(policy.RootElement,"device-a");Assert(true,"Valid audit policy schema");
Reject(()=>SignedDocument.ValidatePolicy(policy.RootElement,"device-b"),"Cross-device policy rejected");
using var expired=JsonDocument.Parse(JsonSerializer.Serialize(document).Replace(document.valid_until,DateTime.UtcNow.AddHours(-1).ToString("O")));
Reject(()=>SignedDocument.ValidatePolicy(expired.RootElement,"device-a"),"Expired policy rejected");
using var unsafePolicy=JsonDocument.Parse(JsonSerializer.Serialize(document).Replace("\"user\"","\"user;whoami\""));
Reject(()=>SignedDocument.ValidatePolicy(unsafePolicy.RootElement,"device-a"),"Unsafe account identifier rejected");
Console.WriteLine($"{passed} contract tests passed. Windows behavior still requires VM verification.");
