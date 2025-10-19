using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Linq;

namespace Analiza_Statica;

public enum SeverityLevel
{
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4
}

public class Vulnerability
{
    public string Id { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public string CodeSnippet { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string CweId { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public List<string> DetectedBy { get; set; } = new();
}

public class AnalysisResult
{
    public string ProjectPath { get; set; } = string.Empty;
    public string ProjectName { get; set; } = string.Empty;
    public DateTime AnalysisDate { get; set; }
    public TimeSpan TotalDuration { get; set; }
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    public Dictionary<string, int> Statistics { get; set; } = new();
    public int FilesAnalyzed { get; set; }
    public int LinesOfCode { get; set; }
}

// ==================== PATTERN ANALYZER ====================

public class PatternAnalyzer
{
    private static readonly Dictionary<string, (string Title, string Description, string Remediation, SeverityLevel Severity, string CWE)> Patterns = new()
    {
        // SQL Injection patterns
        [@"FromSqlRaw\s*\(\s*\$?""[^""]*\{\s*\w+\s*\}"] = (
            "SQL Injection via String Interpolation",
            "Query SQL construit cu string interpolation permite injecție SQL",
            "Utilizați FromSqlInterpolated() sau parametri SQL expliciti",
            SeverityLevel.Critical,
            "CWE-89"
        ),
        [@"FromSqlRaw\s*\(\s*[^@][\w\s+]*\)"] = (
            "Possible SQL Injection",
            "Utilizare FromSqlRaw fără parametri poate permite SQL injection",
            "Verificați că query-ul folosește parametri (@p0, @p1) sau treceți la FromSqlInterpolated",
            SeverityLevel.High,
            "CWE-89"
        ),
        [@"(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+\s*\+"] = (
            "SQL Query String Concatenation",
            "Query SQL construit prin concatenare de stringuri",
            "Utilizați parametri SQL sau ORM cu parametri siguri",
            SeverityLevel.Critical,
            "CWE-89"
        ),
        
        // XSS patterns
        [@"@\(\(MarkupString\)"] = (
            "Cross-Site Scripting (XSS) Risk",
            "Conversie directă la MarkupString fără sanitizare permite XSS",
            "Sanitizați input-ul cu HtmlEncoder sau validați că vine din sursă sigură",
            SeverityLevel.High,
            "CWE-79"
        ),
        [@"\.InnerHtml\s*="] = (
            "Direct HTML Injection",
            "Setare InnerHtml cu date nesanitizate permite XSS",
            "Folosiți TextContent sau sanitizați HTML-ul cu librărie dedicată",
            SeverityLevel.High,
            "CWE-79"
        ),
        
        // Hardcoded secrets
        [@"(password|apikey|api_key|secret|token)\s*=\s*""[^""]{8,}"""] = (
            "Hardcoded Secret",
            "Credențiale hardcoded în cod sursă",
            "Mutați în variabile de mediu, Azure Key Vault sau appsettings securizat",
            SeverityLevel.Critical,
            "CWE-798"
        ),
        [@"(ConnectionString|connString)\s*=\s*""[^""]*password=[^""]+"""] = (
            "Hardcoded Connection String",
            "Connection string cu parolă hardcoded în cod",
            "Folosiți User Secrets, Azure Key Vault sau Environment Variables",
            SeverityLevel.Critical,
            "CWE-798"
        ),
        
        // Path Traversal
        [@"Path\.Combine\([^)]*Request\.|Path\.Combine\([^)]*\[""[^""]*""\]"] = (
            "Path Traversal Risk",
            "Construire cale fișier din input utilizator fără validare",
            "Validați și normalizați căile (Path.GetFullPath, verificare whitelist)",
            SeverityLevel.High,
            "CWE-22"
        ),
        [@"File\.(ReadAllText|WriteAllText|Delete|Open)\([^)]*Request\."] = (
            "Unsafe File Operation",
            "Operație pe fișier cu cale din input utilizator",
            "Validați căile și restricționați la directoare permise",
            SeverityLevel.High,
            "CWE-22"
        ),
        
        // Weak Cryptography
        [@"new\s+(MD5CryptoServiceProvider|SHA1Managed|DESCryptoServiceProvider)"] = (
            "Weak Cryptographic Algorithm",
            "Utilizare algoritm criptografic slab (MD5/SHA1/DES)",
            "Folosiți SHA256, SHA384, SHA512 sau pentru parole: bcrypt/Argon2",
            SeverityLevel.High,
            "CWE-327"
        ),
        [@"HashAlgorithm\.Create\(""(MD5|SHA1)""\)"] = (
            "Weak Hash Algorithm",
            "Algoritm hash deprecat pentru securitate",
            "Folosiți SHA256 sau superior",
            SeverityLevel.Medium,
            "CWE-327"
        ),
        
        // Deserialization
        [@"BinaryFormatter|SoapFormatter|NetDataContractSerializer"] = (
            "Insecure Deserialization",
            "Deserializare nesigură poate permite execuție cod arbitrar",
            "Folosiți System.Text.Json sau validați tipurile deserializate",
            SeverityLevel.Critical,
            "CWE-502"
        ),
        
        // Missing Authorization
        [@"\[HttpPost\]|\[HttpPut\]|\[HttpDelete\](?![\s\S]*?\[Authorize\])"] = (
            "Missing Authorization",
            "Endpoint modificare date fără atribut [Authorize]",
            "Adăugați [Authorize] pe toate endpoint-urile care modifică date",
            SeverityLevel.High,
            "CWE-862"
        ),
        
        // Command Injection
        [@"Process\.Start\([^)]*Request\.|Process\.Start\([^)]*\["""] = (
            "Command Injection Risk",
            "Execuție proces cu parametri din input utilizator",
            "Validați strict input-ul și evitați shell=true",
            SeverityLevel.Critical,
            "CWE-78"
        ),
        
        // CSRF
        [@"\[HttpPost\](?![\s\S]*?\[ValidateAntiForgeryToken\])"] = (
            "Missing CSRF Protection",
            "Endpoint POST fără protecție CSRF",
            "Adăugați [ValidateAntiForgeryToken] pe actions POST",
            SeverityLevel.Medium,
            "CWE-352"
        )
    };

    public List<Vulnerability> AnalyzeFile(string filePath, string content)
    {
        var vulnerabilities = new List<Vulnerability>();
        var lines = content.Split('\n');
        var vulnCounter = 1;

        foreach (var pattern in Patterns)
        {
            var regex = new Regex(pattern.Key, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            var matches = regex.Matches(content);

            foreach (Match match in matches)
            {
                var lineNumber = GetLineNumber(content, match.Index);
                var codeSnippet = GetCodeSnippet(lines, lineNumber);

                vulnerabilities.Add(new Vulnerability
                {
                    Id = $"PAT-{vulnCounter++:D3}",
                    Severity = pattern.Value.Severity,
                    Title = pattern.Value.Title,
                    Description = pattern.Value.Description,
                    FilePath = filePath,
                    LineNumber = lineNumber,
                    CodeSnippet = codeSnippet,
                    Remediation = pattern.Value.Remediation,
                    CweId = pattern.Value.CWE,
                    Category = "Code Pattern Analysis",
                    DetectedBy = new List<string> { "Pattern Analyzer" }
                });
            }
        }

        return vulnerabilities;
    }

    private int GetLineNumber(string content, int index)
    {
        return content.Substring(0, index).Count(c => c == '\n') + 1;
    }

    private string GetCodeSnippet(string[] lines, int lineNumber)
    {
        if (lineNumber <= 0 || lineNumber > lines.Length)
            return "";

        var start = Math.Max(0, lineNumber - 2);
        var end = Math.Min(lines.Length, lineNumber + 1);
        
        return string.Join("\n", lines.Skip(start).Take(end - start));
    }
}

// ==================== DEPENDENCY CHECKER ====================

public class DependencyChecker
{
    private static readonly Dictionary<string, (string CVE, double CVSS, string Description, string FixVersion)> KnownVulnerabilities = new()
    {
        ["Newtonsoft.Json;12.0.3"] = ("CVE-2024-21907", 7.5, "Deserialization of untrusted data", "13.0.3"),
        ["System.Text.Encodings.Web;4.7.0"] = ("CVE-2021-26701", 8.1, ".NET Core Remote Code Execution", "4.7.2"),
        ["System.Text.Encodings.Web;4.7.1"] = ("CVE-2021-26701", 8.1, ".NET Core Remote Code Execution", "4.7.2"),
        ["Microsoft.AspNetCore.Mvc;2.2.0"] = ("CVE-2020-1147", 7.8, "XML External Entity Injection", "3.1.10"),
    };

    public List<Vulnerability> CheckDependencies(string projectPath)
    {
        var vulnerabilities = new List<Vulnerability>();
        var csprojFile = Directory.GetFiles(projectPath, "*.csproj", SearchOption.TopDirectoryOnly).FirstOrDefault();

        if (csprojFile == null)
            return vulnerabilities;

        var content = File.ReadAllText(csprojFile);
        var packageRegex = new Regex(@"<PackageReference\s+Include=""([^""]+)""\s+Version=""([^""]+)""");
        var matches = packageRegex.Matches(content);

        var vulnCounter = 1;
        foreach (Match match in matches)
        {
            var packageName = match.Groups[1].Value;
            var version = match.Groups[2].Value;
            var key = $"{packageName};{version}";

            if (KnownVulnerabilities.TryGetValue(key, out var vulnInfo))
            {
                var severity = vulnInfo.CVSS >= 9.0 ? SeverityLevel.Critical :
                               vulnInfo.CVSS >= 7.0 ? SeverityLevel.High :
                               vulnInfo.CVSS >= 4.0 ? SeverityLevel.Medium : SeverityLevel.Low;

                vulnerabilities.Add(new Vulnerability
                {
                    Id = $"DEP-{vulnCounter++:D3}",
                    Severity = severity,
                    Title = $"Vulnerable Dependency: {packageName}",
                    Description = $"{vulnInfo.Description}\nCVSS Score: {vulnInfo.CVSS}",
                    FilePath = Path.GetFileName(csprojFile),
                    LineNumber = 0,
                    CodeSnippet = $"<PackageReference Include=\"{packageName}\" Version=\"{version}\" />",
                    Remediation = $"Actualizați la versiunea {vulnInfo.FixVersion} sau superioară:\ndotnet add package {packageName} --version {vulnInfo.FixVersion}",
                    CweId = vulnInfo.CVE,
                    Category = "Vulnerable Dependencies",
                    DetectedBy = new List<string> { "Dependency Checker" }
                });
            }
        }

        return vulnerabilities;
    }
}

// ==================== BUILD ANALYZER ====================

public class BuildAnalyzer
{
    public async Task<List<Vulnerability>> AnalyzeWithBuild(string projectPath)
    {
        var vulnerabilities = new List<Vulnerability>();
        var csprojFile = Directory.GetFiles(projectPath, "*.csproj", SearchOption.TopDirectoryOnly).FirstOrDefault();

        if (csprojFile == null)
            return vulnerabilities;

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"build \"{csprojFile}\" /warnaserror-",
                WorkingDirectory = projectPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
                return vulnerabilities;

            var output = await process.StandardOutput.ReadToEndAsync();
            var errors = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            // Parse warnings despre securitate
            var warningRegex = new Regex(@"(.*?)\((\d+),\d+\): warning (CS\d+|SCS\d+): (.*)");
            var combinedOutput = output + "\n" + errors;
            var matches = warningRegex.Matches(combinedOutput);

            var vulnCounter = 1;
            foreach (Match match in matches)
            {
                var file = match.Groups[1].Value;
                var line = int.Parse(match.Groups[2].Value);
                var code = match.Groups[3].Value;
                var message = match.Groups[4].Value;

                // Filtrare doar warnings de securitate
                if (code.StartsWith("SCS") || message.Contains("security", StringComparison.OrdinalIgnoreCase))
                {
                    var severity = code.StartsWith("SCS0") ? SeverityLevel.High : SeverityLevel.Medium;

                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = $"BLD-{vulnCounter++:D3}",
                        Severity = severity,
                        Title = $"Build Warning: {code}",
                        Description = message,
                        FilePath = file,
                        LineNumber = line,
                        CodeSnippet = "",
                        Remediation = "Consultați documentația pentru " + code,
                        CweId = code,
                        Category = "Build Analysis",
                        DetectedBy = new List<string> { "Build Analyzer" }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARNING] Build analysis failed: {ex.Message}");
        }

        return vulnerabilities;
    }
}

// ==================== CONSOLE REPORTER ====================

public class ConsoleReporter
{
    private static readonly Dictionary<SeverityLevel, (string Icon, ConsoleColor Color)> SeverityDisplay = new()
    {
        [SeverityLevel.Critical] = ("🔴", ConsoleColor.Red),
        [SeverityLevel.High] = ("🟠", ConsoleColor.DarkYellow),
        [SeverityLevel.Medium] = ("🟡", ConsoleColor.Yellow),
        [SeverityLevel.Low] = ("🟢", ConsoleColor.Green),
        [SeverityLevel.Info] = ("🔵", ConsoleColor.Blue)
    };

    public void DisplayResults(AnalysisResult result)
    {
        Console.Clear();
        
        PrintHeader();
        PrintProjectInfo(result);
        PrintProgressSummary();
        PrintStatistics(result);
        PrintVulnerabilities(result);
        PrintRecommendations(result);
        PrintFooter(result);
    }

    private void PrintHeader()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║          BLAZOR SECURITY ANALYZER v1.0.0                         ║");
        Console.WriteLine("║          Analiză Statică Automată de Securitate                  ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    private void PrintProjectInfo(AnalysisResult result)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"[INFO] Proiect: {result.ProjectName}");
        Console.WriteLine($"[INFO] Cale: {result.ProjectPath}");
        Console.WriteLine($"[INFO] Fișiere analizate: {result.FilesAnalyzed}");
        Console.WriteLine($"[INFO] Linii de cod: {result.LinesOfCode:N0}");
        Console.WriteLine($"[INFO] Data analiză: {result.AnalysisDate:yyyy-MM-dd HH:mm:ss}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private void PrintProgressSummary()
    {
        Console.WriteLine("════════════════════════════════════════════════════════════════════");
        Console.WriteLine();

        PrintStep("1/3", "Analiză Pattern-Matching", ConsoleColor.Green);
        PrintStep("2/3", "Verificare Dependențe", ConsoleColor.Green);
        PrintStep("3/3", "Analiză Build", ConsoleColor.Green);
        
        Console.WriteLine();
        Console.WriteLine("════════════════════════════════════════════════════════════════════");
    }

    private void PrintStep(string stepNumber, string description, ConsoleColor color)
    {
        Console.Write("[");
        Console.ForegroundColor = color;
        Console.Write(stepNumber);
        Console.ResetColor();
        Console.WriteLine($"] {description}");
    }

    private void PrintStatistics(AnalysisResult result)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("═══════════════════════════ STATISTICI ════════════════════════════");
        Console.ResetColor();
        Console.WriteLine();

        var totalVulns = result.Vulnerabilities.Count;
        var bySeverity = result.Vulnerabilities.GroupBy(v => v.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        // Afișare statistici pe severity
        foreach (var severity in Enum.GetValues<SeverityLevel>())
        {
            var count = bySeverity.GetValueOrDefault(severity, 0);
            var display = SeverityDisplay[severity];
            
            Console.ForegroundColor = display.Color;
            Console.Write($"{display.Icon} {severity,-10}");
            Console.ResetColor();
            Console.WriteLine($": {count,3} {(count == 1 ? "vulnerabilitate" : "vulnerabilități")}");
        }

        Console.WriteLine();
        Console.WriteLine($"Total vulnerabilități: {totalVulns}");
        Console.WriteLine($"Timp execuție: {result.TotalDuration.TotalSeconds:F2} secunde");
        Console.WriteLine();
    }

    private void PrintVulnerabilities(AnalysisResult result)
    {
        if (result.Vulnerabilities.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ Nu s-au găsit vulnerabilități!");
            Console.ResetColor();
            return;
        }

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("════════════════════════ VULNERABILITĂȚI ══════════════════════════");
        Console.ResetColor();
        Console.WriteLine();

        var sortedVulns = result.Vulnerabilities
            .OrderBy(v => v.Severity)
            .ThenBy(v => v.Category)
            .ToList();

        for (int i = 0; i < sortedVulns.Count; i++)
        {
            var vuln = sortedVulns[i];
            var display = SeverityDisplay[vuln.Severity];

            // Header vulnerabilitate
            Console.ForegroundColor = display.Color;
            Console.WriteLine($"{display.Icon} [{vuln.Id}] {vuln.Title}");
            Console.ResetColor();

            // Detalii
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"   Severitate: {vuln.Severity} | CWE: {vuln.CweId} | Categorie: {vuln.Category}");
            Console.WriteLine($"   Fișier: {vuln.FilePath}:{vuln.LineNumber}");
            Console.ResetColor();

            // Descriere
            Console.WriteLine($"   Descriere: {vuln.Description}");

            // Code snippet
            if (!string.IsNullOrWhiteSpace(vuln.CodeSnippet))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"   Cod:");
                var codeLines = vuln.CodeSnippet.Split('\n');
                foreach (var line in codeLines)
                {
                    Console.WriteLine($"     {line}");
                }
                Console.ResetColor();
            }

            // Remediere
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"   Remediere: {vuln.Remediation}");
            Console.ResetColor();

            Console.WriteLine();
        }
    }

    private void PrintRecommendations(AnalysisResult result)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("═════════════════════════ RECOMANDĂRI ═════════════════════════════");
        Console.ResetColor();
        Console.WriteLine();

        var criticalCount = result.Vulnerabilities.Count(v => v.Severity == SeverityLevel.Critical);
        var highCount = result.Vulnerabilities.Count(v => v.Severity == SeverityLevel.High);

        if (criticalCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"⚠️  URGENT: {criticalCount} vulnerabilități CRITICE necesită atenție imediată!");
            Console.ResetColor();
            Console.WriteLine("   • Rezolvați toate vulnerabilitățile critice înainte de deployment");
            Console.WriteLine("   • Acestea pot permite atacuri grave (SQL Injection, RCE, etc.)");
            Console.WriteLine();
        }

        if (highCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"⚠️  IMPORTANT: {highCount} vulnerabilități HIGH severity");
            Console.ResetColor();
            Console.WriteLine("   • Planificați remedierea acestora în următorul sprint");
            Console.WriteLine();
        }

        // Recomandări generale
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("📋 Recomandări generale:");
        Console.ResetColor();
        Console.WriteLine("   1. Activați Security Code Scanning în CI/CD");
        Console.WriteLine("   2. Implementați code review pentru securitate");
        Console.WriteLine("   3. Actualizați dependențele vulnerabile");
        Console.WriteLine("   4. Configurați security headers (CSP, HSTS, etc.)");
        Console.WriteLine("   5. Rulați teste de penetrare periodic");
        Console.WriteLine();
    }

    private void PrintFooter(AnalysisResult result)
    {
        Console.WriteLine("════════════════════════════════════════════════════════════════════");
        Console.WriteLine();
        
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"Raport generat: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"Durată analiză: {result.TotalDuration.TotalSeconds:F2} secunde");
        Console.ResetColor();
        
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("Pentru suport: https://github.com/your-repo/blazor-security-analyzer");
        Console.ResetColor();
        Console.WriteLine();
    }
}

// ==================== MAIN ORCHESTRATOR ====================

public class SecurityAnalyzer
{
    private readonly PatternAnalyzer _patternAnalyzer;
    private readonly DependencyChecker _dependencyChecker;
    private readonly BuildAnalyzer _buildAnalyzer;
    private readonly ConsoleReporter _reporter;

    public SecurityAnalyzer()
    {
        _patternAnalyzer = new PatternAnalyzer();
        _dependencyChecker = new DependencyChecker();
        _buildAnalyzer = new BuildAnalyzer();
        _reporter = new ConsoleReporter();
    }

    public async Task<AnalysisResult> AnalyzeProjectAsync(string projectPath)
    {
        var startTime = DateTime.Now;
        var result = new AnalysisResult
        {
            ProjectPath = projectPath,
            ProjectName = Path.GetFileName(projectPath),
            AnalysisDate = startTime
        };

        Console.WriteLine("[INFO] Inițializare analiză...");
        Console.WriteLine($"[INFO] Cale proiect: {projectPath}");
        Console.WriteLine();

        // Step 1: Analiză pattern-matching
        Console.WriteLine("[STEP 1/3] Analiză Pattern-Matching...");
        var patternVulns = await AnalyzeWithPatternsAsync(projectPath);
        result.Vulnerabilities.AddRange(patternVulns);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ {patternVulns.Count} probleme detectate prin pattern-matching");
        Console.ResetColor();
        Console.WriteLine();

        // Step 2: Verificare dependențe
        Console.WriteLine("[STEP 2/3] Verificare Dependențe...");
        var depVulns = _dependencyChecker.CheckDependencies(projectPath);
        result.Vulnerabilities.AddRange(depVulns);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ {depVulns.Count} vulnerabilități găsite în dependențe");
        Console.ResetColor();
        Console.WriteLine();

        // Step 3: Analiză build
        Console.WriteLine("[STEP 3/3] Analiză Build cu Roslyn...");
        var buildVulns = await _buildAnalyzer.AnalyzeWithBuild(projectPath);
        result.Vulnerabilities.AddRange(buildVulns);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ {buildVulns.Count} warning-uri de securitate din build");
        Console.ResetColor();
        Console.WriteLine();

        result.TotalDuration = DateTime.Now - startTime;

        return result;
    }

    private async Task<List<Vulnerability>> AnalyzeWithPatternsAsync(string projectPath)
    {
        var vulnerabilities = new List<Vulnerability>();
        var extensions = new[] { "*.cs", "*.razor", "*.cshtml" };
        var filesAnalyzed = 0;
        var totalLines = 0;

        foreach (var extension in extensions)
        {
            var files = Directory.GetFiles(projectPath, extension, SearchOption.AllDirectories)
                .Where(f => !f.Contains("\\obj\\") && !f.Contains("\\bin\\"))
                .ToList();

            foreach (var file in files)
            {
                try
                {
                    var content = await File.ReadAllTextAsync(file);
                    var lines = content.Split('\n').Length;
                    totalLines += lines;
                    filesAnalyzed++;

                    var fileVulns = _patternAnalyzer.AnalyzeFile(file, content);
                    vulnerabilities.AddRange(fileVulns);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[WARNING] Nu s-a putut analiza {file}: {ex.Message}");
                }
            }
        }

        Console.WriteLine($"  - Fișiere analizate: {filesAnalyzed}");
        Console.WriteLine($"  - Linii de cod: {totalLines:N0}");

        return vulnerabilities;
    }

    public void DisplayResults(AnalysisResult result)
    {
        _reporter.DisplayResults(result);
    }

    public async Task SaveReportAsync(AnalysisResult result, string outputPath)
    {
        try
        {
            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            await File.WriteAllTextAsync(outputPath, json);
            Console.WriteLine($"[INFO] Raport salvat în: {outputPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Nu s-a putut salva raportul: {ex.Message}");
        }
    }
}

// ==================== PROGRAM ENTRY POINT ====================

class Program
{
    static async Task<int> Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            string projectPath;

            if (args.Length == 0)
            {
                // Mod interactiv
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║          BLAZOR SECURITY ANALYZER v1.0.0                         ║");
                Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine();
                Console.Write("Introduceți calea către proiectul Blazor: ");
                projectPath = Console.ReadLine()?.Trim() ?? "";

                if (string.IsNullOrEmpty(projectPath))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[ERROR] Calea nu poate fi goală!");
                    Console.ResetColor();
                    return 1;
                }
            }
            else
            {
                projectPath = args[0];
            }

            // Accept both directory path and .csproj file path
            if (File.Exists(projectPath) && Path.GetExtension(projectPath).Equals(".csproj", StringComparison.OrdinalIgnoreCase))
            {
                projectPath = Path.GetDirectoryName(projectPath) ?? projectPath;
            }

            // Validare cale
            if (!Directory.Exists(projectPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Directorul nu există: {projectPath}");
                Console.ResetColor();
                return 1;
            }

            // Verificare dacă există fișier .csproj
            var csprojFiles = Directory.GetFiles(projectPath, "*.csproj", SearchOption.TopDirectoryOnly);
            if (csprojFiles.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Nu s-a găsit niciun fișier .csproj în directorul specificat!");
                Console.ResetColor();
                return 1;
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✓ Proiect găsit: {Path.GetFileName(csprojFiles[0])}");
            Console.ResetColor();
            Console.WriteLine();

            // Rulare analiză
            var analyzer = new SecurityAnalyzer();
            var result = await analyzer.AnalyzeProjectAsync(projectPath);

            // Actualizare statistici
            result.FilesAnalyzed = Directory.GetFiles(projectPath, "*.*", SearchOption.AllDirectories)
                .Count(f => f.EndsWith(".cs") || f.EndsWith(".razor") || f.EndsWith(".cshtml"));
            
            result.LinesOfCode = result.FilesAnalyzed * 150; // Aproximare

            // Afișare rezultate
            analyzer.DisplayResults(result);

            // Salvare raport JSON
            var reportsDir = Path.Combine(projectPath, "security-reports");
            Directory.CreateDirectory(reportsDir);
            var reportPath = Path.Combine(reportsDir, $"analysis-{DateTime.Now:yyyy-MM-dd-HHmmss}.json");
            await analyzer.SaveReportAsync(result, reportPath);

            // Return code
            var criticalCount = result.Vulnerabilities.Count(v => v.Severity == SeverityLevel.Critical);
            return criticalCount > 0 ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[FATAL ERROR] {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            Console.ResetColor();
            return 2;
        }
    }
}




