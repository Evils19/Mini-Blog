using System.Collections.Generic;
using System.Linq;

namespace Testig.Core.Models;

public class AnalysisResult
{
    public List<AnalyzerReport> Reports { get; set; } = new();

    public IReadOnlyList<Vulnerability> AllVulnerabilities
        => Reports.SelectMany(r => r.Vulnerabilities).ToList();
}
