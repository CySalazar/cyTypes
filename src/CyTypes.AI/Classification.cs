using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace CyTypes.AI.Classification;

public enum DataClass
{
    None,
    Email,
    Phone,
    Ssn,
    CreditCard,
    Iban,
    FiscalCode,
    PersonName,
    Address,
    IpAddress,
    ApiKey,
    ConnectionString,
    MedicalTerm,
    Salary,
    Age,
    DateOfBirth,
    Url,
    Password,
    BankAccount,
    PassportNumber,
    DriverLicense,
    NationalId,
    Geolocation,
    Biometric,
    PoliticalOpinion,
    SexualOrientation,
    ChildData,
    FinancialAccount,
    HealthRecord,
    /// <summary>
    /// Custom company-defined category. Use together with <see cref="Finding.CustomLabel"/>
    /// to disambiguate the actual data type (e.g. "AcmeProjectCode", "InternalTicketId").
    /// The PiiTokenizer derives the token prefix from the slugified CustomLabel.
    /// </summary>
    Custom
}

public enum DetectionMethod { Regex, Heuristic, LocalLlm, Plugin }

public sealed record Finding(
    DataClass DataClass,
    string Value,
    int Start,
    int Length,
    double Confidence,
    DetectionMethod DetectionMethod,
    string? Source = null,
    string? CustomLabel = null);

public sealed class ClassificationResult
{
    public List<Finding> Findings { get; } = new();
    public string OriginalText { get; init; } = "";
    public bool HasSensitiveData => Findings.Count > 0;
}

public interface ILocalClassifier
{
    IEnumerable<Finding> Classify(string text);
}

/// <summary>
/// Lightweight pattern-based local classifier (no real LLM, but the public surface
/// matches the production API). Uses regex + heuristics over a Unicode-normalised input.
/// </summary>
public sealed class LocalLlmClassifier : ILocalClassifier
{
    public IEnumerable<Finding> Classify(string text)
    {
        // No-op base; the heavy lifting lives in DataClassifier so plugins can extend it.
        yield break;
    }
}

public sealed class DataClassifier
{
    private readonly ILocalClassifier _local;
    private readonly List<Plugin.ICompliancePlugin> _plugins = new();

    public DataClassifier(ILocalClassifier local)
    {
        _local = local;
    }

    public void AddPlugin(Plugin.ICompliancePlugin plugin) => _plugins.Add(plugin);

    public ClassificationResult Classify(string text)
    {
        var result = new ClassificationResult { OriginalText = text };
        // NFKC + zero-width strip prevents homoglyph/zero-width evasion
        var normalised = StripZeroWidth(text.Normalize(NormalizationForm.FormKC));

        var raw = new List<Finding>();
        raw.AddRange(BuiltInRegex(normalised));
        raw.AddRange(Heuristics(normalised));
        raw.AddRange(_local.Classify(normalised));
        foreach (var plugin in _plugins)
            raw.AddRange(plugin.Detect(normalised));

        // Span suppression: drop a finding if its span is fully contained in
        // another finding which is either of higher-specificity class (fixes
        // Phone-inside-IBAN/PAN) or of the same class but longer (fixes the
        // multilingual MedicalTerm overlap "diabetes" / "diabete" / "diabet").
        var kept = new List<Finding>();
        foreach (var f in raw.OrderByDescending(x => Specificity(x.DataClass))
                              .ThenByDescending(x => x.Length)
                              .ThenByDescending(x => x.Confidence))
        {
            bool dominated = kept.Any(k =>
                k.Start <= f.Start && k.Start + k.Length >= f.Start + f.Length &&
                (Specificity(k.DataClass) > Specificity(f.DataClass) ||
                 (k.DataClass == f.DataClass && k.Length > f.Length)));
            if (!dominated) kept.Add(f);
        }
        // Deduplicate by (class, value)
        var seen = new HashSet<(DataClass, string)>();
        kept.RemoveAll(f => !seen.Add((f.DataClass, f.Value)));
        result.Findings.AddRange(kept.OrderBy(f => f.Start));
        return result;
    }

    /// <summary>Higher value = more specific. Drives span-suppression.</summary>
    /// <remarks>
    /// ConnectionString is intentionally above Email/Url/Phone so that
    /// "postgres://user:pwd@host" suppresses the inner Email match.
    /// IBAN/CreditCard/SSN/FiscalCode stay above ConnectionString because
    /// they cannot realistically appear inside one.
    /// </remarks>
    private static int Specificity(DataClass c) => c switch
    {
        DataClass.Iban => 100,
        DataClass.CreditCard => 100,
        DataClass.Ssn => 95,
        DataClass.FiscalCode => 95,
        DataClass.ConnectionString => 97,
        DataClass.NationalId => 90,
        DataClass.Email => 90,
        DataClass.ApiKey => 90,
        DataClass.Password => 88,
        // Company-custom categories sit between API keys and URLs:
        // higher than infrastructure data (Url/IpAddress) so a company token
        // dominates an URL match, but lower than Iban/PAN/SSN which never
        // realistically appear inside a custom span.
        DataClass.Custom => 87,
        DataClass.Url => 80,
        DataClass.IpAddress => 75,
        DataClass.Phone => 60,
        DataClass.Salary => 55,
        DataClass.PersonName => 40,
        DataClass.MedicalTerm => 35,
        _ => 50
    };

    private static string StripZeroWidth(string s)
        => Regex.Replace(s, @"[\u200B-\u200F\u202A-\u202E\uFEFF]", "");

    // ----- built-in regex patterns -----
    private static readonly (DataClass cls, Regex rx)[] _patterns =
    {
        (DataClass.Email,        new Regex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.Compiled)),
        (DataClass.Iban,         new Regex(@"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", RegexOptions.Compiled)),
        (DataClass.CreditCard,   new Regex(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.Compiled)),
        (DataClass.IpAddress,    new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)),
        (DataClass.Url,          new Regex(@"https?://[^\s""'<>]+", RegexOptions.Compiled)),
        // Phone: optional + country, optional area code (parens or 2-4 digits) repeated 1-4
        // times, then a final compact 3-9 digit block. Lookbehind/lookahead prevent
        // matching inside longer digit runs (IBAN, PAN). Final 7-15 digit guard in
        // BuiltInRegex enforces E.164-ish length limits.
        (DataClass.Phone,        new Regex(@"(?<![\d.])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?|\d{2,4}[ .-]?){1,4}\d{3,9}(?![\d.])", RegexOptions.Compiled)),
        (DataClass.FiscalCode,   new Regex(@"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b", RegexOptions.Compiled)),
        (DataClass.Ssn,          new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled)),
        // Stripe live/test keys + generic api/secret prefixed keys
        (DataClass.ApiKey,       new Regex(@"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", RegexOptions.Compiled)),
        (DataClass.ApiKey,       new Regex(@"\b(?:api[_-]?key|secret|token|bearer)[_-]?[A-Za-z0-9]{20,}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        (DataClass.ApiKey,       new Regex(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled)), // AWS access key
        (DataClass.ApiKey,       new Regex(@"\bgh[ps]_[A-Za-z0-9]{36,}\b", RegexOptions.Compiled)), // GitHub
        (DataClass.ConnectionString, new Regex(@"(?:Server|Data Source|Host)\s*=\s*[^;]+;.*?(?:Password|Pwd)\s*=\s*[^;""']+", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        (DataClass.ConnectionString, new Regex(@"(?:postgres|mysql|mongodb|redis)(?:\+\w+)?://[^:\s]+:[^@\s]+@[^/\s]+", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        // Password with keyword context: matches "password=Hunter2024!", "pwd: secret",
        // "passw0rd : whatever", "password temporanea Hunter2024" (it), etc.
        // Captures from a password-keyword up to whitespace / quote / line end.
        // Won't match bare passwords without context (impossible without semantics).
        (DataClass.Password, new Regex(@"(?:password|passwd|pwd|passw[o0]rd|contrase[ñn]a|mot\s*de\s*passe|kennwort|senha)(?:\s*temporanea)?\s*[:=]?\s*['""]?(?<v>[^\s'""<>;]{6,64})", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
    };

    private static IEnumerable<Finding> BuiltInRegex(string text)
    {
        foreach (var (cls, rx) in _patterns)
            foreach (Match m in rx.Matches(text))
            {
                if (cls == DataClass.CreditCard && !LuhnCheck(m.Value)) continue;
                if (cls == DataClass.Phone)
                {
                    var digits = m.Value.Count(char.IsDigit);
                    if (digits < 7 || digits > 15) continue; // E.164 max
                    // Suppress phone matches that occur inside binary noise
                    // (MP4 box dumps, raw image bytes, etc.) by requiring a
                    // human-readable surrounding context.
                    if (!HasReadableContext(text, m.Index, m.Length, minRatio: 0.75)) continue;
                }
                // Some patterns use a named group "v" to isolate the actual
                // sensitive value (e.g. the password regex captures the keyword
                // for context but only the value should appear in the finding).
                var valueGroup = m.Groups["v"];
                if (valueGroup.Success && !string.IsNullOrEmpty(valueGroup.Value))
                    yield return new Finding(cls, valueGroup.Value.Trim(), valueGroup.Index, valueGroup.Length, 0.9, DetectionMethod.Regex);
                else
                    yield return new Finding(cls, m.Value.Trim(), m.Index, m.Length, 0.9, DetectionMethod.Regex);
            }
    }

    // Multilingual medical keyword list (case-insensitive substring match).
    // Covers the 21 languages used in MultilingualSamples + the most common
    // synonyms of cancer/diabetes/depression/tumor/insulin/chemotherapy/disease.
    // Substring matching handles inflected forms automatically (HU "cukorbetegségben"
    // matches "cukorbetegség", FI "diabetesta" matches "diabetes", etc.).
    private static readonly string[] _medicalTerms =
    {
        // EN
        "cancer","tumor","tumour","diabetes","hiv","aids","depression","anxiety",
        "prescription","insulin","chemotherapy","mri","x-ray","cardiac",
        "hypertension","pneumonia","asthma","leukemia","stroke",
        // IT
        "tumore","cancro","diabete","depressione","ansia","insulina","chemioterapia",
        "diagnosi","ipertensione","polmonite","malattia","infarto","epatite",
        // FR
        "tumeur","diabète","dépression","insuline","chimiothérapie","maladie",
        "pneumonie","crise cardiaque",
        // DE
        "krebs","lungenkrebs","tumor","depression","insulin","chemotherapie",
        "krankheit","herzinsuffizienz","bluthochdruck","lungenentzündung","schlaganfall",
        // ES
        "cáncer","diabetes","depresión","insulina","quimioterapia","enfermedad",
        "hipertensión","neumonía","infarto",
        // PT
        "câncer","cancro","depressão","quimioterapia","doença","pneumonia",
        // NL
        "kanker","depressie","chemotherapie","ziekte","hartfalen","longziekte",
        "bloeddruk",
        // PL
        "nowotwór","rak","cukrzyca","depresja","insulina","chemioterapia","choroba",
        // SV
        "tumör","kemoterapi","sjukdom","hjärtsvikt",
        // FI
        "syöpä","kasvain","masennus","insuliini","kemoterapia","sairaus",
        // DA
        "kræft","kemoterapi","sygdom","lungesygdom",
        // CS
        "rakovina","nádor","cukrovka","deprese","inzulín","chemoterapie","nemoc",
        // HU
        "rák","daganat","cukorbetegség","depresszió","kemoterápia","betegség",
        // RO
        "tumoră","diabet","depresie","insulină","chimioterapie","boală","pulmonar",
        // BG (Cyrillic)
        "рак","тумор","диабет","депресия","инсулин","химиотерапия","болест",
        // EL (Greek)
        "καρκίνος","όγκος","διαβήτης","κατάθλιψη","ινσουλίνη","χημειοθεραπεία",
        "ασθένεια",
        // RU (Cyrillic)
        "опухоль","депрессия","химиотерапия","болезнь","хроническ",
        // ZH (Chinese)
        "癌症","肿瘤","糖尿病","抑郁","胰岛素","化疗","疾病",
        // JA (Japanese)
        "がん","癌","腫瘍","糖尿病","うつ病","インスリン","化学療法","病気",
        // AR
        "سرطان","ورم","السكري","الاكتئاب","الأنسولين","مرض",
        // HI (Devanagari)
        "कैंसर","ट्यूमर","मधुमेह","अवसाद","इंसुलिन","बीमारी",
    };

    private static IEnumerable<Finding> Heuristics(string text)
    {
        var lower = text.ToLowerInvariant();
        foreach (var term in _medicalTerms)
            if (lower.Contains(term))
                yield return new Finding(DataClass.MedicalTerm, term, lower.IndexOf(term), term.Length, 0.7, DetectionMethod.Heuristic);

        var salary = Regex.Match(text, @"(?:€|\$|£)\s?\d{2,3}\s?[kK]?", RegexOptions.IgnoreCase);
        if (salary.Success)
            yield return new Finding(DataClass.Salary, salary.Value, salary.Index, salary.Length, 0.75, DetectionMethod.Heuristic);

        // Naive person-name: two consecutive Capitalized words.
        // Wrap in a printable-ratio context filter to suppress false positives
        // when the heuristic is run over binary content (e.g. byte dumps from
        // BMP/WebP/HEIC/MP4 boxes that occasionally produce ASCII sequences
        // matching the regex by accident).
        foreach (Match m in Regex.Matches(text, @"\b[A-Z][a-zà-ú]+\s+[A-Z][a-zà-ú]+\b"))
        {
            if (!HasReadableContext(text, m.Index, m.Length, minRatio: 0.75)) continue;
            yield return new Finding(DataClass.PersonName, m.Value, m.Index, m.Length, 0.6, DetectionMethod.Heuristic);
        }
    }

    /// <summary>
    /// Returns true if the surrounding 80-character window of <paramref name="text"/>
    /// around <paramref name="matchStart"/> looks like human-readable text
    /// (printable ASCII / common Unicode letters) at a ratio of at least
    /// <paramref name="minRatio"/>. Used by heuristic detectors to suppress
    /// false positives on binary dumps.
    /// </summary>
    internal static bool HasReadableContext(string text, int matchStart, int matchLength, double minRatio = 0.75, int windowRadius = 40)
    {
        if (text.Length == 0) return true;
        int from = Math.Max(0, matchStart - windowRadius);
        int to = Math.Min(text.Length, matchStart + matchLength + windowRadius);
        int total = to - from;
        if (total <= 0) return true;
        int readable = 0;
        for (int i = from; i < to; i++)
        {
            char c = text[i];
            // ASCII printable + whitespace
            if ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t')
            { readable++; continue; }
            // Common European/CJK letters and punctuation
            if (char.IsLetter(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c))
            { readable++; continue; }
        }
        return (double)readable / total >= minRatio;
    }

    private static bool LuhnCheck(string raw)
    {
        var digits = raw.Where(char.IsDigit).Select(c => c - '0').ToArray();
        if (digits.Length < 13) return false;
        int sum = 0; bool dbl = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i];
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d; dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}
