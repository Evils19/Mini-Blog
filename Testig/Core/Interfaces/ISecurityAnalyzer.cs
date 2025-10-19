using System.Threading;
using System.Threading.Tasks;
using Testig.Core.Models;

namespace Testig.Core.Interfaces;

public interface ISecurityAnalyzer
{
    string Name { get; }
    Task<AnalyzerReport> AnalyzeAsync(string projectPath, CancellationToken ct = default);
}
