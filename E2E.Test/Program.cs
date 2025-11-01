using System.Text.Json;
using OpenQA.Selenium;
using OpenQA.Selenium.Edge;
using OpenQA.Selenium.Support.UI;
using System.Diagnostics;

namespace E2E.Test;

public class Program
{
    private const int DefaultTimeoutSec = 10;
    private static bool _verbose;
    private static int _stepDelayMs;
    private static int _betweenTestsMs;
    private static string _outputDir = string.Empty;
    private static bool _saveHtml;

    public static int Main(string[] args)
    {
        var baseUrl = ResolveBaseUrl();
        var headless = IsHeadless();
        // CLI override: --headed/--no-headless принудительно выключает headless, --headless включает
        if (HasCliFlag("--headed") || HasCliFlag("--no-headless")) headless = false;
        if (HasCliFlag("--headless")) headless = true;
        var holdMs = ResolveHoldMs();
        _verbose = IsVerbose();
        _stepDelayMs = ResolveStepDelayMs();
        _betweenTestsMs = ResolveBetweenTestsMs();
        _saveHtml = ShouldSaveHtml();
        _outputDir = EnsureOutputDir();

        Log($"BaseUrl: {baseUrl}");
        Log($"Headless: {headless}");
        Log($"Verbose: {_verbose}");
        Log($"StepDelayMs: {_stepDelayMs}");
        Log($"BetweenTestsMs: {_betweenTestsMs}");
        Log($"OutputDir: {_outputDir}");
        if (!headless && holdMs > 0)
            Log($"HoldMs: {holdMs}");

        using var driver = CreateEdgeDriver(headless);
        if (!headless)
        {
            try { driver.Manage().Window.Maximize(); } catch { }
        }
        var results = new List<TestResult>();

        results.Add(RunTest(driver, baseUrl, "Lab index", TestLabIndex));
        results.Add(RunTest(driver, baseUrl, "SQL Injection page", TestSqlInjectionPage));
        results.Add(RunTest(driver, baseUrl, "XSS page", TestXssPage));
        results.Add(RunTest(driver, baseUrl, "Errors page", TestErrorsPage));
        results.Add(RunTest(driver, baseUrl, "Auth page", (d, b) => Navigate(d, b, "/Lab/auth")));
        results.Add(RunTest(driver, baseUrl, "CSRF page", (d, b) => Navigate(d, b, "/Lab/csrf")));
        results.Add(RunTest(driver, baseUrl, "Logic page", (d, b) => Navigate(d, b, "/Lab/logic")));
        results.Add(RunTest(driver, baseUrl, "Session page", (d, b) => Navigate(d, b, "/Lab/session")));
        results.Add(RunTest(driver, baseUrl, "Source page", (d, b) => Navigate(d, b, "/Lab/source")));
        results.Add(RunTest(driver, baseUrl, "ThirdParty page", (d, b) => Navigate(d, b, "/Lab/third-party")));

        Console.WriteLine("\n[E2E] Test summary:");
        foreach (var r in results)
        {
            Console.WriteLine(r.Passed
                ? $"  [+] {r.Name} PASS ({r.DurationMs} ms)"
                : $"  [-] {r.Name} FAIL -> {r.Error} ({r.DurationMs} ms)");
        }

        var failed = results.Count(r => !r.Passed);
        Console.WriteLine($"\n[E2E] Completed: {results.Count - failed} passed, {failed} failed");

        if (!headless && holdMs > 0)
        {
            Log($"Удерживаю окно браузера {holdMs} мс...");
            Thread.Sleep(holdMs);
        }
        return failed == 0 ? 0 : 1;
    }

    // --- Individual tests ---

    private static void TestLabIndex(IWebDriver driver, string baseUrl)
    {
        Navigate(driver, baseUrl, "/Lab");
        DelayStep("after navigate /Lab");
        var links = driver.FindElements(By.CssSelector("a[href^='/Lab/'], a[href^='/lab/']"));
        Log($"/Lab: найдено ссылок на подлабы: {links.Count}");
        SaveSnapshot(driver, "lab-index");
        if (links.Count == 0)
            throw new Exception("No lab links found on /Lab page");
    }

    private static void TestSqlInjectionPage(IWebDriver driver, string baseUrl)
    {
        Navigate(driver, baseUrl, "/Lab/sql-injection");
        DelayStep("after navigate /Lab/sql-injection");
        var input = WaitForElement(driver, By.CssSelector("input[type='text'], input:not([type]), textarea"), 5);
        if (input is null)
        {
            Log("SQLi: поле ввода не найдено");
            SaveSnapshot(driver, "sqlinj-no-input");
            return;
        }
        Log("SQLi: поле ввода найдено, ввожу пробу");
        input.Clear();
        input.SendKeys("' OR '1'='1 -- ");
        SaveSnapshot(driver, "sqlinj-before-submit");

        var submit = TryFind(driver, "button[type='submit'], input[type='submit'], button, input[type='button']");
        if (submit is not null)
        {
            Log("SQLi: нажимаю submit");
            submit.Click();
        }
        else
        {
            Log("SQLi: submit не найден, жду обновления страницы");
        }

        WaitForNetworkIdle(driver);
        DelayStep("after submit /Lab/sql-injection");
        // Попробуем посчитать результаты
        var items = driver.FindElements(By.CssSelector("ul.list-group li.list-group-item"));
        Log($"SQLi: элементов в результатах: {items.Count}");
        SaveSnapshot(driver, "sqlinj-after-submit");
        EnsurePageInteractive(driver);
    }

    private static void TestXssPage(IWebDriver driver, string baseUrl)
    {
        Navigate(driver, baseUrl, "/Lab/xss");
        DelayStep("after navigate /Lab/xss");
        var payload = "<b>XSS_TEST_123</b>";
        var input = WaitForElement(driver, By.CssSelector("textarea, input[type='text'], input:not([type])"), 5);
        if (input is null)
        {
            Log("XSS: поле ввода не найдено");
            SaveSnapshot(driver, "xss-no-input");
            return;
        }
        Log("XSS: поле ввода найдено, ввожу маркер");
        input.Clear();
        input.SendKeys(payload);
        SaveSnapshot(driver, "xss-before-submit");

        var submit = TryFind(driver, "button[type='submit'], input[type='submit'], button, input[type='button']");
        submit?.Click();
        if (submit is null) Log("XSS: submit не найден, продолжаю ожидание");

        WaitForNetworkIdle(driver);
        DelayStep("after submit /Lab/xss");
        var pageSource = driver.PageSource;
        var reflected = !string.IsNullOrWhiteSpace(pageSource) && pageSource.Contains(payload, StringComparison.OrdinalIgnoreCase);
        Log($"XSS: маркер{(reflected ? " " : " не ")}обнаружен в исходнике страницы");
        SaveSnapshot(driver, reflected ? "xss-marker-reflected" : "xss-marker-not-reflected");
        if (_saveHtml) SaveHtml(driver, reflected ? "xss-marker-reflected" : "xss-marker-not-reflected");
        EnsurePageInteractive(driver);
    }

    private static void TestErrorsPage(IWebDriver driver, string baseUrl)
    {
        Navigate(driver, baseUrl, "/Lab/errors");
        DelayStep("after navigate /Lab/errors");
        SaveSnapshot(driver, "errors-page");
        EnsurePageInteractive(driver);
    }

    // --- Helpers ---

    private static TestResult RunTest(IWebDriver driver, string baseUrl, string name, Action<IWebDriver, string> action)
    {
        var sw = Stopwatch.StartNew();
        var safeName = SafeName(name);
        Log($"=== Тест: {name} ===");
        try
        {
            action(driver, baseUrl);
            sw.Stop();
            Log($"Тест {name}: PASS за {sw.ElapsedMilliseconds} мс");
            if (_betweenTestsMs > 0) Delay(_betweenTestsMs, $"между тестами после {name}");
            return TestResult.Pass(name, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            sw.Stop();
            Log($"Тест {name}: FAIL за {sw.ElapsedMilliseconds} мс -> {ex.Message}");
            SaveSnapshot(driver, $"{safeName}-FAIL");
            if (_saveHtml) SaveHtml(driver, $"{safeName}-FAIL");
            if (_betweenTestsMs > 0) Delay(_betweenTestsMs, $"между тестами после {name} (fail)");
            return TestResult.Fail(name, ex.Message, sw.ElapsedMilliseconds);
        }
    }

    private static IWebDriver CreateEdgeDriver(bool headless)
    {
        var options = new EdgeOptions();
        if (headless)
            options.AddArgument("--headless=new");
        else
            options.AddArgument("--start-maximized");
        options.AddArgument("--window-size=1600,1000");
        options.AcceptInsecureCertificates = true;

        var service = EdgeDriverService.CreateDefaultService();
        service.HideCommandPromptWindow = true;
        var driver = new EdgeDriver(service, options, TimeSpan.FromSeconds(60));
        driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(2);
        driver.Manage().Timeouts().PageLoad = TimeSpan.FromSeconds(30);
        return driver;
    }

    private static bool HasCliFlag(string flag)
    {
        return Environment.GetCommandLineArgs().Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
    }

    private static void Navigate(IWebDriver driver, string baseUrl, string path)
    {
        var url = CombineUrl(baseUrl, path);
        Log($"Навигация: {url}");
        driver.Navigate().GoToUrl(url);
        WaitForReady(driver);
    }

    private static void WaitForReady(IWebDriver driver)
    {
        var wait = new WebDriverWait(new SystemClock(), driver, TimeSpan.FromSeconds(DefaultTimeoutSec), TimeSpan.FromMilliseconds(200));
        wait.Until(d =>
        {
            try
            {
                var stateObj = ((IJavaScriptExecutor)d).ExecuteScript("return document.readyState");
                var state = stateObj as string;
                return state is "complete" or "interactive";
            }
            catch
            {
                return false;
            }
        });
    }

    private static void WaitForNetworkIdle(IWebDriver driver, int quietMs = 400)
    {
        WaitForReady(driver);
        Delay(quietMs, "network idle padding");
    }

    private static void EnsurePageInteractive(IWebDriver driver)
    {
        _ = driver.Title;
        var body = driver.FindElements(By.TagName("body"));
        if (body.Count == 0) throw new Exception("No <body> found");
    }

    private static IWebElement? TryFind(IWebDriver driver, string cssSelector, int timeoutSec = 3)
    {
        try
        {
            var wait = new WebDriverWait(new SystemClock(), driver, TimeSpan.FromSeconds(timeoutSec), TimeSpan.FromMilliseconds(200));
            return wait.Until(d =>
            {
                var el = d.FindElements(By.CssSelector(cssSelector)).FirstOrDefault();
                return el is { Displayed: true, Enabled: true } ? el : null;
            });
        }
        catch
        {
            return null;
        }
    }

    private static IWebElement? WaitForElement(IWebDriver driver, By by, int timeoutSec = 10)
    {
        try
        {
            var wait = new WebDriverWait(new SystemClock(), driver, TimeSpan.FromSeconds(timeoutSec), TimeSpan.FromMilliseconds(200));
            return wait.Until(d =>
            {
                var el = d.FindElements(by).FirstOrDefault();
                return el is { Displayed: true, Enabled: true } ? el : null;
            });
        }
        catch
        {
            return null;
        }
    }

    private static string CombineUrl(string baseUrl, string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return baseUrl.TrimEnd('/');
        return baseUrl.TrimEnd('/') + "/" + path.TrimStart('/');
    }

    private static string ResolveBaseUrl()
    {
        var env = Environment.GetEnvironmentVariable("E2E_BASEURL");
        if (!string.IsNullOrWhiteSpace(env)) return env;

        try
        {
            var jsonPath = FindSiblingWebAppSettings();
            if (jsonPath is not null && File.Exists(jsonPath))
            {
                using var fs = File.OpenRead(jsonPath);
                using var doc = JsonDocument.Parse(fs);
                if (doc.RootElement.TryGetProperty("E2E", out var e2E) &&
                    e2E.TryGetProperty("BaseUrl", out var baseUrlProp) &&
                    baseUrlProp.GetString() is { } bu && !string.IsNullOrWhiteSpace(bu))
                {
                    return bu;
                }
            }
        }
        catch { }

        return "http://localhost:5048";
    }

    private static string? FindSiblingWebAppSettings()
    {
        var baseDir = AppContext.BaseDirectory;
        var dir = new DirectoryInfo(baseDir);
        for (int i = 0; i < 6 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir.FullName, "MyBlazorServerBlog", "appsettings.Development.json");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    private static bool IsHeadless()
    {
        var env = Environment.GetEnvironmentVariable("E2E_HEADLESS");
        if (string.IsNullOrWhiteSpace(env)) return true;
        return env.Trim() is not "0" and not "false";
    }

    private static bool IsVerbose()
    {
        var env = Environment.GetEnvironmentVariable("E2E_VERBOSE");
        if (string.IsNullOrWhiteSpace(env)) return true; // по умолчанию включено
        return env.Trim() is not "0" and not "false";
    }

    private static int ResolveHoldMs()
    {
        var env = Environment.GetEnvironmentVariable("E2E_HOLD_MS");
        if (int.TryParse(env, out var ms) && ms > 0)
            return Math.Min(ms, 600_000);
        return 0;
    }

    private static int ResolveStepDelayMs()
    {
        var env = Environment.GetEnvironmentVariable("E2E_STEP_DELAY_MS");
        if (int.TryParse(env, out var ms) && ms >= 0) return Math.Min(ms, 10_000);
        // по умолчанию 1000 мс, чтобы видеть шаги
        return 1000;
    }

    private static int ResolveBetweenTestsMs()
    {
        var env = Environment.GetEnvironmentVariable("E2E_BETWEEN_TESTS_MS");
        if (int.TryParse(env, out var ms) && ms >= 0) return Math.Min(ms, 30_000);
        return 1000; // пауза между тестами по умолчанию
    }

    private static void DelayStep(string reason)
    {
        if (_stepDelayMs > 0) Delay(_stepDelayMs, reason);
    }

    private static void Delay(int ms, string reason)
    {
        Log($"Задержка {ms} мс ({reason})");
        Thread.Sleep(ms);
    }

    private static void Log(string message)
    {
        if (!_verbose) { Console.WriteLine($"[E2E] {message}"); return; }
        var ts = DateTime.Now.ToString("HH:mm:ss.fff");
        Console.WriteLine($"[E2E {ts}] {message}");
    }

    private static string EnsureOutputDir()
    {
        var configured = Environment.GetEnvironmentVariable("E2E_OUTPUT_DIR");
        string dir;
        if (!string.IsNullOrWhiteSpace(configured)) dir = configured!;
        else dir = Path.Combine(Environment.CurrentDirectory, "e2e-output", DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SaveSnapshot(IWebDriver driver, string name)
    {
        try
        {
            if (driver is ITakesScreenshot ts)
            {
                var file = Path.Combine(_outputDir, SafeName(name) + ".png");
                var shot = ts.GetScreenshot();
                shot.SaveAsFile(file);
                Log($"Скриншот: {file}");
            }
        }
        catch (Exception ex)
        {
            Log($"Не удалось сохранить скриншот: {ex.Message}");
        }
    }

    private static void SaveHtml(IWebDriver driver, string name)
    {
        try
        {
            var html = driver.PageSource ?? string.Empty;
            var file = Path.Combine(_outputDir, SafeName(name) + ".html");
            File.WriteAllText(file, html);
            Log($"HTML сохранён: {file}");
        }
        catch (Exception ex)
        {
            Log($"Не удалось сохранить HTML: {ex.Message}");
        }
    }

    private static bool ShouldSaveHtml()
    {
        var env = Environment.GetEnvironmentVariable("E2E_SAVE_HTML");
        return !string.IsNullOrWhiteSpace(env) && env.Trim() is not "0" and not "false";
    }

    private static string SafeName(string name)
    {
        foreach (var ch in Path.GetInvalidFileNameChars()) name = name.Replace(ch, '_');
        return name.Replace(' ', '_');
    }

    private record TestResult(string Name, bool Passed, string? Error, long DurationMs)
    {
        public static TestResult Pass(string name, long ms) => new(name, true, null, ms);
        public static TestResult Fail(string name, string? err, long ms) => new(name, false, err, ms);
    }
}