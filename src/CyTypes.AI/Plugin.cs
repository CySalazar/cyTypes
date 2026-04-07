using System.Text.RegularExpressions;
using CyTypes.AI.Classification;

namespace CyTypes.AI.Plugin;

public enum DataAction { Allow, Tokenize, Redact, Block }
public enum Severity { Info, Low, Medium, High, Critical }

public sealed record ComplianceRule(DataClass DataClass, DataAction Action, Severity Severity, string Description);

public interface ICompliancePlugin
{
    string Id { get; }
    string Name { get; }
    IReadOnlyList<ComplianceRule> GetRules();
    IEnumerable<Finding> Detect(string text);
}

public abstract class CompliancePluginBase : ICompliancePlugin
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    private readonly List<ComplianceRule> _rules = new();
    protected void Rule(DataClass cls, DataAction action, Severity sev, string desc)
        => _rules.Add(new ComplianceRule(cls, action, sev, desc));
    public IReadOnlyList<ComplianceRule> GetRules() { EnsureRules(); return _rules; }

    private bool _built;
    private void EnsureRules() { if (_built) return; _built = true; BuildRules(); }
    protected abstract void BuildRules();

    /// <summary>Override to add plugin-specific regex detection.</summary>
    public virtual IEnumerable<Finding> Detect(string text) { yield break; }

    protected static IEnumerable<Finding> Match(string text, Regex rx, DataClass cls, double conf, string source)
    {
        foreach (Match m in rx.Matches(text))
            yield return new Finding(cls, m.Value, m.Index, m.Length, conf, DetectionMethod.Plugin, source);
    }
}

public sealed class GdprPlugin : CompliancePluginBase
{
    public override string Id => "GDPR";
    public override string Name => "EU General Data Protection Regulation";
    protected override void BuildRules()
    {
        Rule(DataClass.Email, DataAction.Tokenize, Severity.High, "Email is personal data");
        Rule(DataClass.PersonName, DataAction.Tokenize, Severity.High, "Name is personal data");
        Rule(DataClass.Phone, DataAction.Tokenize, Severity.High, "Phone is personal data");
        Rule(DataClass.IpAddress, DataAction.Tokenize, Severity.Medium, "IP is personal data (Recital 30)");
        Rule(DataClass.Address, DataAction.Tokenize, Severity.High, "Address is personal data");
        Rule(DataClass.HealthRecord, DataAction.Block, Severity.Critical, "Special category data (Art. 9)");
        Rule(DataClass.Biometric, DataAction.Block, Severity.Critical, "Biometric data (Art. 9)");
    }
}

public sealed class Nis2Plugin : CompliancePluginBase
{
    public override string Id => "NIS2";
    public override string Name => "EU NIS2 Directive";
    protected override void BuildRules()
    {
        Rule(DataClass.ApiKey, DataAction.Block, Severity.Critical, "API keys must not leak");
        Rule(DataClass.ConnectionString, DataAction.Block, Severity.Critical, "Connection strings must not leak");
        Rule(DataClass.Password, DataAction.Block, Severity.Critical, "Credentials must not leak");
    }
}

public sealed class HipaaPlugin : CompliancePluginBase
{
    public override string Id => "HIPAA";
    public override string Name => "US HIPAA";
    protected override void BuildRules()
    {
        Rule(DataClass.MedicalTerm, DataAction.Tokenize, Severity.High, "PHI");
        Rule(DataClass.HealthRecord, DataAction.Block, Severity.Critical, "PHI");
        Rule(DataClass.DateOfBirth, DataAction.Tokenize, Severity.High, "PHI identifier");
    }
}

public sealed class CcpaPlugin : CompliancePluginBase
{
    public override string Id => "CCPA";
    public override string Name => "California CCPA";
    protected override void BuildRules()
    {
        Rule(DataClass.Email, DataAction.Tokenize, Severity.Medium, "Personal info");
        Rule(DataClass.Geolocation, DataAction.Tokenize, Severity.Medium, "Geolocation");
    }
}

public sealed class EPrivacyPlugin : CompliancePluginBase
{
    public override string Id => "ePrivacy";
    public override string Name => "EU ePrivacy";
    protected override void BuildRules()
    {
        Rule(DataClass.IpAddress, DataAction.Tokenize, Severity.Medium, "Electronic communication metadata");
    }
}

public sealed class DoraPlugin : CompliancePluginBase
{
    public override string Id => "DORA";
    public override string Name => "EU DORA (financial)";
    protected override void BuildRules()
    {
        Rule(DataClass.FinancialAccount, DataAction.Block, Severity.Critical, "Financial account");
        Rule(DataClass.Iban, DataAction.Tokenize, Severity.High, "IBAN");
    }
}

public sealed class EuAiActPlugin : CompliancePluginBase
{
    public override string Id => "EUAIACT";
    public override string Name => "EU AI Act";
    protected override void BuildRules()
    {
        Rule(DataClass.Biometric, DataAction.Block, Severity.Critical, "Prohibited biometric categorisation");
        Rule(DataClass.PoliticalOpinion, DataAction.Block, Severity.Critical, "Prohibited social scoring input");
    }
}

public sealed class SoxPlugin : CompliancePluginBase
{
    public override string Id => "SOX";
    public override string Name => "US Sarbanes-Oxley";
    protected override void BuildRules()
    {
        Rule(DataClass.FinancialAccount, DataAction.Block, Severity.High, "Financial data");
    }
}

public sealed class CoppaPlugin : CompliancePluginBase
{
    public override string Id => "COPPA";
    public override string Name => "US COPPA (children)";
    protected override void BuildRules()
    {
        Rule(DataClass.ChildData, DataAction.Block, Severity.Critical, "Data of minors under 13");
        Rule(DataClass.Age, DataAction.Tokenize, Severity.High, "Age generalisation");
    }
}

public sealed class LgpdPlugin : CompliancePluginBase
{
    public override string Id => "LGPD";
    public override string Name => "Brazil LGPD";
    protected override void BuildRules()
    {
        Rule(DataClass.NationalId, DataAction.Tokenize, Severity.High, "CPF");
        Rule(DataClass.Email, DataAction.Tokenize, Severity.Medium, "Personal data");
    }
    public override IEnumerable<Finding> Detect(string text)
        => Match(text, new Regex(@"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), DataClass.NationalId, 0.95, Id);
}

public sealed class PiplPlugin : CompliancePluginBase
{
    public override string Id => "PIPL";
    public override string Name => "China PIPL";
    protected override void BuildRules()
    {
        Rule(DataClass.NationalId, DataAction.Block, Severity.Critical, "PRC ID");
        Rule(DataClass.Phone, DataAction.Tokenize, Severity.High, "Phone");
    }
}

public sealed class PopiaPlugin : CompliancePluginBase
{
    public override string Id => "POPIA";
    public override string Name => "South Africa POPIA";
    protected override void BuildRules()
    {
        Rule(DataClass.NationalId, DataAction.Tokenize, Severity.High, "ID number");
    }
}

public sealed class AppiPlugin : CompliancePluginBase
{
    public override string Id => "APPI";
    public override string Name => "Japan APPI";
    protected override void BuildRules()
    {
        Rule(DataClass.PersonName, DataAction.Tokenize, Severity.High, "Personal data");
        Rule(DataClass.Address, DataAction.Tokenize, Severity.High, "Personal data");
    }
}

public sealed class PdpaPlugin : CompliancePluginBase
{
    private readonly string _country;
    public PdpaPlugin(string country) { _country = country; }
    public override string Id => $"PDPA-{_country}";
    public override string Name => $"PDPA ({_country})";
    protected override void BuildRules()
    {
        Rule(DataClass.NationalId, DataAction.Tokenize, Severity.High, "NRIC");
        Rule(DataClass.Phone, DataAction.Tokenize, Severity.Medium, "Phone");
    }
}

public sealed class PciDssPlugin : CompliancePluginBase
{
    public override string Id => "PCIDSS";
    public override string Name => "PCI DSS";
    protected override void BuildRules()
    {
        Rule(DataClass.CreditCard, DataAction.Block, Severity.Critical, "PAN must not be transmitted");
    }
}

public sealed class MifidPsd2Plugin : CompliancePluginBase
{
    public override string Id => "MIFID-PSD2";
    public override string Name => "MiFID II / PSD2";
    protected override void BuildRules()
    {
        Rule(DataClass.Iban, DataAction.Tokenize, Severity.High, "Payment account");
        Rule(DataClass.FinancialAccount, DataAction.Tokenize, Severity.High, "Investment account");
    }
}

public sealed class CustomPlugin : CompliancePluginBase
{
    public override string Id { get; }
    public override string Name { get; }
    private readonly List<ComplianceRule> _custom = new();

    public CustomPlugin(string id, string name) { Id = id; Name = name; }

    public CustomPlugin AddRule(DataClass cls, DataAction action, Severity sev, string desc)
    {
        _custom.Add(new ComplianceRule(cls, action, sev, desc));
        return this;
    }

    protected override void BuildRules()
    {
        foreach (var r in _custom) Rule(r.DataClass, r.Action, r.Severity, r.Description);
    }
}
