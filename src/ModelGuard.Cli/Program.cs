using System.Text.Json;
using ModelGuard.Core;
var root = Environment.GetEnvironmentVariable("MODEL_GUARD_ROOT") ?? Defaults.DataRoot;
var store = new DataStore(root); var runtime = new OllamaRuntime();
if (args.Length == 0 || args[0] is "help" or "--help") { Help(); return 0; }
try {
 switch (args[0].ToLowerInvariant()) {
  case "init": store.Initialize(); Console.WriteLine(root); break;
  case "inventory": case "status": var ms = await runtime.InventoryAsync(); await store.SaveInventoryAsync(ms); foreach (var m in ms) Console.WriteLine($"{m.Name}\t{m.Digest}\t{store.StatusFor(m)}"); break;
  case "qualify": if (args.Length < 3) throw new ArgumentException("qualify requires <model> <corpus.json>"); var model = (await runtime.InventoryAsync()).Single(m => m.Name.Equals(args[1], StringComparison.OrdinalIgnoreCase)); using (var meta = await runtime.MetadataAsync(model.Name)) await store.SaveMetadataAsync(model, meta); var report = await new QualificationEngine(runtime, store).RunAsync(model, await Corpus.LoadAsync(args[2])); Console.WriteLine(JsonSerializer.Serialize(report, Defaults.Json)); break;
  case "inspect": if (args.Length < 2) throw new ArgumentException("inspect requires <package-path>"); Console.WriteLine(JsonSerializer.Serialize(await StaticInspector.InspectAsync(args[1]), Defaults.Json)); break;
  default: throw new ArgumentException("Unknown command: " + args[0]);
 } return 0;
} catch (Exception ex) { Console.Error.WriteLine("ModelGuard: " + ex.Message); return 2; }
static void Help() => Console.WriteLine("ModelGuard CLI\n  init\n  inventory\n  status\n  qualify <model> <corpus.json>\n  inspect <package-path>\nMODEL_GUARD_ROOT overrides T:\\ForensicAI\\ModelQualification");
