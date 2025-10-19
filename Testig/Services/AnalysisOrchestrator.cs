using Testig.Core.Interfaces;
using Testig.Core.Models;

namespace Testig.Services;

public class AnalysisOrchestrator
{
    private readonly IReadOnlyList<ISecurityAnalyzer> _analyzers;

    public AnalysisOrchestrator(IEnumerable<ISecurityAnalyzer> analyzers)
    {
        _analyzers = analyzers.ToList();
    }

    public async Task<AnalysisResult> RunAsync(string projectPath, CancellationToken ct = default)
    {
        var result = new AnalysisResult();
        foreach (var analyzer in _analyzers)
        {
            var report = await analyzer.AnalyzeAsync(projectPath, ct);
            result.Reports.Add(report);
        }
        return result;
    }
}
