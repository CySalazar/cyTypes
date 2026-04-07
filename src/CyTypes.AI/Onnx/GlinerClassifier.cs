using CyTypes.AI.Classification;

namespace CyTypes.AI.Onnx;

/// <summary>
/// Multilingual zero-shot NER classifier built on top of <see cref="GlinerOnnxModel"/>.
///
/// Implements <see cref="ILocalClassifier"/> so it can plug straight into
/// <see cref="DataClassifier"/> alongside the regex layer.
///
/// Holds a fixed list of (entity-text, DataClass, threshold) tuples; on each
/// <see cref="Classify"/> call it runs a single GLiNER forward pass on the
/// input text using all entity texts at once and emits one
/// <see cref="Finding"/> per surviving span.
/// </summary>
public sealed class GlinerClassifier : ILocalClassifier, IDisposable
{
    private readonly GlinerOnnxModel _model;
    private readonly bool _ownsModel;

    /// <summary>
    /// Maps the prompt strings GLiNER will see (in English, since the model
    /// is multilingual but its label-side is English) to the internal
    /// <see cref="DataClass"/> taxonomy. Order here matches the model output
    /// channels — every label costs 1 prompt slot, max 25 per call.
    /// </summary>
    private static readonly (string Label, DataClass Class, float Threshold)[] DefaultEntities =
    {
        ("email address",                   DataClass.Email,             0.55f),
        ("phone number",                    DataClass.Phone,             0.55f),
        // Higher threshold for PersonName: GLiNER tends to over-fire on
        // pronouns and articles like "She", "The patient", "His", etc.
        ("person name",                     DataClass.PersonName,        0.70f),
        ("postal address",                  DataClass.Address,           0.50f),
        ("credit card number",              DataClass.CreditCard,        0.55f),
        ("iban bank account",               DataClass.Iban,              0.55f),
        ("national identification number",  DataClass.NationalId,        0.50f),
        ("medical condition",               DataClass.MedicalTerm,       0.50f),
        ("medication",                      DataClass.MedicalTerm,       0.50f),
        ("financial account",               DataClass.FinancialAccount,  0.50f),
        ("political opinion",               DataClass.PoliticalOpinion,  0.50f),
        ("sexual orientation",              DataClass.SexualOrientation, 0.50f),
        ("biometric identifier",            DataClass.Biometric,         0.45f),
        ("ip address",                      DataClass.IpAddress,         0.55f),
        ("api key or secret",               DataClass.ApiKey,            0.55f),
        ("database connection string",      DataClass.ConnectionString,  0.55f),
    };

    private readonly string[] _labels;
    private readonly DataClass[] _classes;
    private readonly float[] _thresholds;

    public GlinerClassifier(GlinerOnnxModel model, bool ownsModel = true)
    {
        _model = model;
        _ownsModel = ownsModel;
        _labels     = DefaultEntities.Select(e => e.Label).ToArray();
        _classes    = DefaultEntities.Select(e => e.Class).ToArray();
        _thresholds = DefaultEntities.Select(e => e.Threshold).ToArray();
    }

    /// <summary>Convenience: ensure the model is downloaded and load it from cache.</summary>
    public static GlinerClassifier LoadDefault(Action<string>? log = null)
    {
        var (modelPath, spmPath) = ModelDownloader.GetOrDownload(log);
        var model = new GlinerOnnxModel(modelPath, spmPath);
        return new GlinerClassifier(model);
    }

    /// <summary>Try to load the default model; return null if download/load fails.</summary>
    public static GlinerClassifier? TryLoadDefault(Action<string>? log = null)
    {
        try { return LoadDefault(log); }
        catch (Exception ex) { log?.Invoke($"[gliner] disabled: {ex.Message}"); return null; }
    }

    // Multilingual stoplist of pronouns / articles / determiners that GLiNER
    // sometimes mis-classifies as PersonName. All lowercase, all 1-3 word forms.
    private static readonly HashSet<string> _personNameStop = new(StringComparer.OrdinalIgnoreCase)
    {
        // EN
        "she","he","it","they","we","i","you","the","a","an","this","that","these","those",
        "his","her","its","their","our","my","your","the patient","the user","the doctor",
        // IT
        "lui","lei","loro","noi","io","tu","il","la","lo","gli","le","un","una",
        // FR
        "il","elle","ils","elles","le","la","les","un","une","des",
        // DE
        "er","sie","es","wir","ich","du","der","die","das","den","dem","ein","eine",
        // ES
        "él","ella","ellos","nosotros","yo","tú","el","la","los","las","un","una",
        // PT
        "ele","ela","eles","nós","eu","tu","o","a","os","as","um","uma",
        // NL
        "hij","zij","wij","ik","jij","de","het","een",
    };

    public IEnumerable<Finding> Classify(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) yield break;

        // Single forward pass with all labels — GLiNER supports up to max_types=25.
        // We use the lowest threshold of all labels here; per-label thresholds are
        // re-applied below to filter the output.
        float minThreshold = _thresholds.Min();
        List<GlinerOnnxModel.EntitySpan> spans;
        try { spans = _model.Run(text, _labels, minThreshold); }
        catch { yield break; }

        // Map GLiNER labels back to DataClass + drop spans below the per-label threshold
        for (int i = 0; i < spans.Count; i++)
        {
            var s = spans[i];
            int li = Array.IndexOf(_labels, s.Label);
            if (li < 0) continue;
            if (s.Score < _thresholds[li]) continue;

            // Filter pronoun/article false positives for PersonName
            if (_classes[li] == DataClass.PersonName && _personNameStop.Contains(s.Text.Trim()))
                continue;

            yield return new Finding(
                _classes[li],
                s.Text,
                s.CharStart,
                s.CharLength,
                s.Score,
                DetectionMethod.LocalLlm,
                "gliner-multi-v2.1");
        }
    }

    public void Dispose() { if (_ownsModel) _model.Dispose(); }
}
