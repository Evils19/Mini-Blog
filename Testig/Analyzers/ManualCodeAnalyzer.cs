using System.Text.RegularExpressions;
using Testig.Core.Interfaces;
using Testig.Core.Models;

namespace Testig.Analyzers;

public class ManualCodeAnalyzer : ISecurityAnalyzer
{
    public string Name => "Manual Pattern Analyzer";

    private static readonly Regex DangerousSqlRegex = new(
        @"FromSqlRaw\s*\(|ExecuteSqlRaw\s*\(|ExecuteSqlInterpolated\s*\(",
        RegexOptions.Compiled);

    private static readonly Regex MarkupStringRegex = new(
        @"MarkupString\s*\(", RegexOptions.Compiled);

    private static readonly Regex InnerHtmlRegex = new(
        @"innerHTML\s*=", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Detect potential hardcoded secrets (API keys, tokens, passwords)
    private static readonly Regex HardcodedSecretRegex = new(
        "(?i)(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{16,}['\"]?",
        RegexOptions.Compiled);

    public async Task<AnalyzerReport> AnalyzeAsync(string projectPath, CancellationToken ct = default)
    {
        var report = new AnalyzerReport { AnalyzerName = Name, Success = true };
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var files = Directory.EnumerateFiles(projectPath, "*.*", SearchOption.AllDirectories)
                .Where(p => (p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".razor", StringComparison.OrdinalIgnoreCase))
                            && !p.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar)
                            && !p.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar))
                .ToList();

            int idx = 1;
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var lines = await File.ReadAllLinesAsync(file, ct);
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    if (DangerousSqlRegex.IsMatch(line))
                    {
                        report.Vulnerabilities.Add(new Vulnerability
                        {
                            Id = $"MANUAL-{idx++:000}",
                            Severity = SeverityLevel.High,
                            Title = "Potential Raw SQL usage",
                            Description = "Detectată utilizare FromSqlRaw/ExecuteSqlRaw care poate cauza SQL Injection dacă parametrii nu sunt validați.",
                            FilePath = file,
                            LineNumber = i + 1,
                            Code = line.Trim(),
                            Remediation = "Folosiți interogări parametrizate sau FromSqlInterpolated cu parametri validați.",
                            CweId = "CWE-89",
                            DetectedBy = new List<string> { Name },
                            Category = "Injection"
                        });
                    }

                    if (MarkupStringRegex.IsMatch(line) || InnerHtmlRegex.IsMatch(line))
                    {
                        report.Vulnerabilities.Add(new Vulnerability
                        {
                            Id = $"MANUAL-{idx++:000}",
                            Severity = SeverityLevel.High,
                            Title = "Potential XSS (raw HTML rendering)",
                            Description = "MarkupString/innerHTML poate introduce XSS dacă se afișează input ne-sanitizat.",
                            FilePath = file,
                            LineNumber = i + 1,
                            Code = line.Trim(),
                            Remediation = "Evitați redarea HTML ne-sanitizat sau sanitizați conținutul înainte de afișare.",
                            CweId = "CWE-79",
                            DetectedBy = new List<string> { Name },
                            Category = "XSS"
                        });
                    }

                    if (HardcodedSecretRegex.IsMatch(line))
                    {
                        report.Vulnerabilities.Add(new Vulnerability
                        {
                            Id = $"MANUAL-{idx++:000}",
                            Severity = SeverityLevel.Critical,
                            Title = "Hardcoded secret detected",
                            Description = "Chei secrete sau token-uri par a fi hardcodate în cod.",
                            FilePath = file,
                            LineNumber = i + 1,
                            Code = line.Trim(),
                            Remediation = "Mută secretele în configurare securizată (env vars, Key Vault) și nu le păstra în cod.",
                            CweId = "CWE-798",
                            DetectedBy = new List<string> { Name },
                            Category = "Secrets"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            report.Success = false;
            report.ErrorMessage = ex.Message;
        }
        finally
        {
            sw.Stop();
            report.ExecutionTime = sw.Elapsed;
        }

        return report;
    }
}
