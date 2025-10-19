namespace Testig;

using System;
using System.Linq;
using Testig.Analyzers;
using Testig.Core.Models;
using Testig.Services;

static class Program
{
    static async Task<int> Main(string[] args)
    {

        string? projectArgPath = null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--project", StringComparison.OrdinalIgnoreCase))
            {
                projectArgPath = args[i + 1];
                break;
            }
        }

        string scanRoot = projectArgPath ?? GetDefaultBlazorProjectRoot();
        if (!Directory.Exists(scanRoot))
        {
            Console.WriteLine($"[ERR] Proiectul nu a fost gasit: {scanRoot}");
            return 4; // invalid project
        }

        // Инициализация и запуск анализаторов
        var orchestrator = new AnalysisOrchestrator(new[]
        {
            new ManualCodeAnalyzer()
        });

        var result = await orchestrator.RunAsync(scanRoot);

        // Отчет в консоль
        ConsoleReporter.Display(result, scanRoot);

        // Exit code: 1 если есть Critical, иначе 0
        var critical = result.AllVulnerabilities.Count(v => v.Severity == SeverityLevel.Critical);
        return critical > 0 ? 1 : 0;
    }

    private static string GetDefaultBlazorProjectRoot()
    {
        // Попытка найти папку MyBlazorServerBlog (в корне репозитория)
        // Точка старта — рабочая директория процесса
        var cwd = Environment.CurrentDirectory;
        // Вариант 1: ../MyBlazorServerBlog
        var candidate = Path.GetFullPath(Path.Combine(cwd, "..", "MyBlazorServerBlog"));
        if (Directory.Exists(candidate)) return candidate;
        // Вариант 2: подняться на уровень выше от bin/Debug/... до корня проекта Testig
        var fromBin = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "MyBlazorServerBlog"));
        if (Directory.Exists(fromBin)) return fromBin;
        // Fallback: текущая директория
        return cwd;
    }
}