namespace Testig.Core.Models;

public class AnalyzerReport
{
    public string AnalyzerName { get; set; } = string.Empty;
    public bool Success { get; set; }
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    public TimeSpan ExecutionTime { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
}
