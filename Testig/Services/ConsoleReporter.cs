using System;
using System.IO;
using System.Linq;
using Testig.Core.Models;

namespace Testig.Services;

public static class ConsoleReporter
{
    public static void Display(AnalysisResult result, string projectRoot)
    {
        Console.WriteLine("\n==== Blazor Security Analyzer (Testig) ====");
        var all = result.AllVulnerabilities;
        Console.WriteLine($"Au fost gasite vulnerabilitati: {all.Count}");

        foreach (var grp in all.GroupBy(v => v.Severity).OrderBy(g => g.Key))
        {
            Console.WriteLine($"  {grp.Key}: {grp.Count()}");
        }

        if (all.Count == 0)
        {
            Console.WriteLine("Nu au fost gasite vulnerabilitati.");
            return;
        }

        Console.WriteLine("\n-- Detalii--");
        foreach (var v in all.OrderBy(v => v.Severity))
        {
            var rel = MakeRelative(v.FilePath, projectRoot);
            Console.WriteLine($"[{v.Severity}] {v.Title} ({v.Id})");
            Console.WriteLine($"  {rel}:{v.LineNumber}");
            if (!string.IsNullOrWhiteSpace(v.Description))
                Console.WriteLine($"  {v.Description}");
            if (!string.IsNullOrWhiteSpace(v.Code))
                Console.WriteLine($"  Code: {v.Code}");
            if (!string.IsNullOrWhiteSpace(v.Remediation))
                Console.WriteLine($"  Fix: {v.Remediation}");
            Console.WriteLine();
        }
    }

    private static string MakeRelative(string path, string root)
    {
        try
        {
            var rel = Path.GetRelativePath(root, path);
            return string.IsNullOrEmpty(rel) ? path : rel;
        }
        catch
        {
            return path;
        }
    }
}

