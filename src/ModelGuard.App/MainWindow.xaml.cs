using System.Windows;
using ModelGuard.Core;
namespace ModelGuard.App;
public partial class MainWindow : Window
{
 private readonly DataStore _store; private readonly OllamaRuntime _runtime = new();
 public MainWindow() { InitializeComponent(); var root = Environment.GetEnvironmentVariable("MODEL_GUARD_ROOT") ?? Defaults.DataRoot; _store = new(root); RootLabel.Text = root; }
 private async void Discover_Click(object sender, RoutedEventArgs e) { try { StatusText.Text = "Discovering…"; await Refresh(); StatusText.Text = $"Discovered {ModelsGrid.Items.Count} model(s). Decisions are bound to exact digests."; } catch (Exception ex) { StatusText.Text = "Ollama is unavailable: " + ex.Message; } }
 private async void Qualify_Click(object sender, RoutedEventArgs e) { if (ModelsGrid.SelectedItem is not Row row) { StatusText.Text = "Select a model first."; return; } try { StatusText.Text = "Running synthetic tests…"; var path = System.IO.Path.Combine(AppContext.BaseDirectory, "corpus", "synthetic-v1.json"); using (var meta = await _runtime.MetadataAsync(row.Model.Name)) await _store.SaveMetadataAsync(row.Model, meta); var r = await new QualificationEngine(_runtime, _store).RunAsync(row.Model, await Corpus.LoadAsync(path)); StatusText.Text = $"{r.Status}: {r.Score:0.0}/100. {r.PolicyReason}"; await Refresh(); } catch (Exception ex) { StatusText.Text = "Qualification stopped: " + ex.Message; } }
 private async Task Refresh() { var models = await _runtime.InventoryAsync(); await _store.SaveInventoryAsync(models); ModelsGrid.ItemsSource = models.Select(m => new Row(m, _store.StatusFor(m))).ToList(); }
 private sealed record Row(ModelIdentity Model, ApprovalStatus Status) { public string Name => Model.Name; public string Digest => Model.Digest; public string Size => $"{Model.Size / 1_073_741_824d:0.0} GB"; }
}
