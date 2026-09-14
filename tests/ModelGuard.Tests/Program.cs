using ModelGuard.Core;
var failures = new List<string>();
void Check(bool condition, string name) { Console.WriteLine($"{(condition ? "PASS" : "FAIL")} {name}"); if (!condition) failures.Add(name); }
var a = new ModelIdentity("m:tag", "sha256:aaaaaaaaaaaaaaaaaa", 1, DateTimeOffset.UtcNow);
var b = a with { Digest = "sha256:bbbbbbbbbbbbbbbbbb" };
Check(a.RegistryKey != b.RegistryKey, "digest change creates a new registry key");
var root = Path.Combine(Path.GetTempPath(), "ModelGuardTests", Guid.NewGuid().ToString());
Check(new DataStore(root).StatusFor(a) == ApprovalStatus.NotYetQualified, "unknown digest is unqualified");
var p = Path.Combine(root, "synthetic.pkl"); Directory.CreateDirectory(root); await File.WriteAllTextAsync(p, "synthetic only");
var inspection = await StaticInspector.InspectAsync(p);
Check(inspection.Findings.Any(x => x.Code == "UNSAFE_SERIALIZATION"), "unsafe serialization is rejected without loading");
Directory.Delete(root, true);
return failures.Count == 0 ? 0 : 1;
