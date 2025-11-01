using System.Diagnostics;
using Microsoft.Extensions.Hosting;

namespace MyBlazorServerBlog.Services;

public class E2EOnStartupHostedService : IHostedService
{
    private readonly ILogger<E2EOnStartupHostedService> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IConfiguration _config;
    private Task? _runner;

    public E2EOnStartupHostedService(ILogger<E2EOnStartupHostedService> logger, IHostApplicationLifetime lifetime, IConfiguration config)
    {
        _logger = logger;
        _lifetime = lifetime;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_config.GetValue("E2E:RunOnStartup", false))
        {
            return Task.CompletedTask;
        }

        _lifetime.ApplicationStarted.Register(() =>
        {
            _runner = Task.Run(RunAsync);
        });
        return Task.CompletedTask;
    }

    private async Task RunAsync()
    {
        try
        {
            var baseUrl = _config["E2E:BaseUrl"] ?? "http://localhost:5048";
            _logger.LogInformation("[E2E] Aștept disponibilitatea aplicației la {BaseUrl}...", baseUrl);

            using var http = new HttpClient();
            for (var i = 0; i < 60; i++)
            {
                try
                {
                    var resp = await http.GetAsync(baseUrl.TrimEnd('/') + "/healthz");
                    if (resp.IsSuccessStatusCode) break;
                }
                catch { /* ignore */ }
                await Task.Delay(1000);
            }

            // Определяем корень решения, чтобы запустить dotnet test E2E.Test
            var cwd = Directory.GetCurrentDirectory();
            string? solutionRoot = null;
            // Попытка 1: на уровень выше от проекта
            var candidate = Path.GetFullPath(Path.Combine(cwd, ".."));
            if (Directory.Exists(Path.Combine(candidate, "E2E.Test"))) solutionRoot = candidate;
            // Попытка 2: текущая
            if (solutionRoot is null && Directory.Exists(Path.Combine(cwd, "E2E.Test"))) solutionRoot = cwd;
            // Попытка 3: от базовой директории
            var baseDir = AppContext.BaseDirectory;
            if (solutionRoot is null)
            {
                var cand2 = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
                if (Directory.Exists(Path.Combine(cand2, "E2E.Test"))) solutionRoot = cand2;
            }

            var projPath = solutionRoot is null
                ? "E2E.Test/E2E.Test.csproj"
                : Path.Combine(solutionRoot, "E2E.Test", "E2E.Test.csproj");

            _logger.LogInformation("[E2E] Lancez: dotnet test {Proj}", projPath);
            var psi = new ProcessStartInfo("dotnet", $"test \"{projPath}\" --nologo")
            {
                WorkingDirectory = solutionRoot ?? Directory.GetCurrentDirectory(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["TEST_BASE_URL"] = baseUrl;

            using var proc = Process.Start(psi)!;
            proc.OutputDataReceived += (_, a) => { if (a.Data != null) _logger.LogInformation("[E2E] {Line}", a.Data); };
            proc.ErrorDataReceived += (_, a) => { if (a.Data != null) _logger.LogError("[E2E] {Line}", a.Data); };
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            await proc.WaitForExitAsync();
            _logger.LogInformation("[E2E] dotnet test завершился с кодом {Code}", proc.ExitCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[E2E] Ошибка запуска автотестов");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return _runner ?? Task.CompletedTask;
    }
}

