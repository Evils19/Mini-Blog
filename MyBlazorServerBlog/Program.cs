using Microsoft.EntityFrameworkCore;
using System.Globalization;
using MyBlazorServerBlog.Data;
using MyBlazorServerBlog.Models;
using Syncfusion.Blazor;
using MyBlazorServerBlog.Services; // добавлено

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
// Syncfusion Blazor
builder.Services.AddSyncfusionBlazor();


builder.Services.Configure<VulnerabilitiesOptions>(builder.Configuration.GetSection("Vulnerabilities"));
builder.Services.AddSingleton<VulnerabilityToggleService>();

// EF Core + SQLite
builder.Services.AddDbContext<BlogDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddHttpClient();

var app = builder.Build();

// Получаем переключатели уязвимостей
var toggles = app.Services.GetRequiredService<VulnerabilityToggleService>();

var supportedCultures = new[] { new CultureInfo("ro"), new CultureInfo("en") };
app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("ro"),
    SupportedCultures = supportedCultures,
    SupportedUICultures = supportedCultures
});

// Ensure DB created
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<BlogDbContext>();
    db.Database.EnsureCreated();

    // Seed demo data
    if (!db.Posts.Any())
    {
        db.Posts.AddRange(
            new Post
            {
                Title = "Добро пожаловать в блог",
                Content = "<p>Это первый пост вашего Blazor Server блога на EF Core + SQLite.</p>",
                CreatedAt = DateTime.UtcNow,
                IsPublished = true
            },
            new Post
            {
                Title = "Как редактировать и добавлять посты",
                Content = "<p>Перейдите в <strong>Админка</strong> → <em>Новый пост</em> и создайте запись.</p>",
                CreatedAt = DateTime.UtcNow,
                IsPublished = true
            }
        );
        db.SaveChanges();
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    // В Dev даем опцию показать подробные ошибки намеренно
    if (toggles.VerboseErrors)
    {
        app.UseDeveloperExceptionPage();
    }
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

// Учебный эндпоинт: бросает исключение для проверки Verbose Errors
app.MapGet("/lab/throw", () =>
{
    throw new InvalidOperationException("Eroare de test din /lab/throw (laborator)");
}).WithName("LabThrow");

// Учебный эндпоинт: демонстрация утечки исходного кода
app.MapGet("/lab/source", async () =>
{
    if (!toggles.SourceCodeDisclosure)
    {
        return Results.NotFound();
    }
    var path = Path.Combine(AppContext.BaseDirectory, "Program.cs");
    if (!File.Exists(path))
    {
        // Пытаемся найти Program.cs в корне проекта
        var alt = Path.Combine(AppContext.BaseDirectory, "..", "MyBlazorServerBlog", "Program.cs");
        path = File.Exists(alt) ? Path.GetFullPath(alt) : path;
    }
    if (!File.Exists(path)) return Results.NotFound();
    var text = await File.ReadAllTextAsync(path);
    return Results.Text(text, "text/plain");
}).WithName("LabSource");

// Группа для демонстрации CSRF
var labCsrf = app.MapGroup("/lab/csrf");
labCsrf.MapGet("/token", (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    // Простой токен в cookie (для демо). В реале использовать встроенный Antiforgery.
    var token = Convert.ToHexString(Guid.NewGuid().ToByteArray());
    ctx.Response.Cookies.Append("lab-csrf-token", token, new CookieOptions
    {
        HttpOnly = false,
        Secure = ctx.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/"
    });
    return Results.Ok(new { token, mode = svc.Csrf ? "Vulnerable" : "Secure" });
}).WithName("LabCsrfToken");

// Хранимая в памяти заметка как цель CSRF
string? csrfNote = null;

labCsrf.MapPost("/update-note", async (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    string body;
    using (var sr = new StreamReader(ctx.Request.Body))
        body = await sr.ReadToEndAsync();
    var note = System.Web.HttpUtility.ParseQueryString(body)["note"] ?? body; // поддержка form-urlencoded и raw

    if (!svc.Csrf)
    {
        // Secure: требуем совпадения токена из заголовка и cookie
        var header = ctx.Request.Headers["X-CSRF-Token"].ToString();
        var cookie = ctx.Request.Cookies["lab-csrf-token"];
        if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(cookie) || !string.Equals(header, cookie, StringComparison.Ordinal))
        {
            return Results.BadRequest(new { message = "CSRF token invalid sau lipsă" });
        }
    }
    // Vulnerable: не проверяем токен вовсе
    csrfNote = note;
    return Results.Ok(new { message = "Notă actualizată", note = csrfNote });
}).WithName("LabCsrfUpdate");

labCsrf.MapGet("/note", () => Results.Ok(new { note = csrfNote ?? "(gol)" })).WithName("LabCsrfNote");

// Minimal API 
var api = app.MapGroup("/api");

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", time = DateTime.UtcNow }))
   .WithName("Healthz");

api.MapGet("/posts", async (BlogDbContext db, int? skip, int? take, bool? published, string? q) =>
{
    var query = db.Posts.AsQueryable();
    if (published.HasValue) query = query.Where(p => p.IsPublished == published.Value);
    if (!string.IsNullOrWhiteSpace(q)) query = query.Where(p => p.Title.Contains(q) || p.Content.Contains(q));
    query = query.OrderByDescending(p => p.CreatedAt);
    if (skip.HasValue) query = query.Skip(Math.Max(0, skip.Value));
    if (take.HasValue) query = query.Take(Math.Clamp(take.Value, 1, 200));
    var data = await query.Select(p => new { p.Id, p.Title, p.CreatedAt, p.UpdatedAt, p.IsPublished }).ToListAsync();
    return Results.Ok(data);
}).WithName("GetPosts");

api.MapGet("/posts/{id:int}", async (BlogDbContext db, int id) =>
{
    var p = await db.Posts.Where(x => x.Id == id)
        .Select(x => new { x.Id, x.Title, x.Content, x.CreatedAt, x.UpdatedAt, x.IsPublished })
        .FirstOrDefaultAsync();
    return p is null ? Results.NotFound() : Results.Ok(p);
}).WithName("GetPostById");

api.MapPost("/posts", async (BlogDbContext db, Post body) =>
{
    if (string.IsNullOrWhiteSpace(body.Title) || string.IsNullOrWhiteSpace(body.Content))
        return Results.BadRequest(new { message = "Title și Content sunt obligatorii" });
    body.Id = 0;
    body.CreatedAt = DateTime.UtcNow;
    body.UpdatedAt = null;
    db.Posts.Add(body);
    await db.SaveChangesAsync();
    return Results.Created($"/api/posts/{body.Id}", new { body.Id });
}).WithName("CreatePost");

api.MapPut("/posts/{id:int}", async (BlogDbContext db, int id, Post body) =>
{
    var p = await db.Posts.FindAsync(id);
    if (p is null) return Results.NotFound();
    if (string.IsNullOrWhiteSpace(body.Title) || string.IsNullOrWhiteSpace(body.Content))
        return Results.BadRequest(new { message = "Title și Content sunt obligatorii" });
    p.Title = body.Title;
    p.Content = body.Content;
    p.IsPublished = body.IsPublished;
    p.UpdatedAt = DateTime.UtcNow;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).WithName("UpdatePost");

api.MapDelete("/posts/{id:int}", async (BlogDbContext db, int id) =>
{
    var p = await db.Posts.FindAsync(id);
    if (p is null) return Results.NotFound();
    db.Posts.Remove(p);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).WithName("DeletePost");

api.MapGet("/posts/{postId:int}/comments", async (BlogDbContext db, int postId, int? skip, int? take) =>
{
    var exists = await db.Posts.AnyAsync(p => p.Id == postId);
    if (!exists) return Results.NotFound();
    IQueryable<Comment> q2 = db.Comments
        .Where(c => c.PostId == postId)
        .OrderByDescending(c => c.CreatedAt);
    if (skip.HasValue) q2 = q2.Skip(Math.Max(0, skip.Value));
    if (take.HasValue) q2 = q2.Take(Math.Clamp(take.Value, 1, 200));
    var items = await q2.Select(c => new { c.Id, c.Author, c.Content, c.CreatedAt }).ToListAsync();
    return Results.Ok(items);
}).WithName("GetComments");

api.MapPost("/posts/{postId:int}/comments", async (BlogDbContext db, int postId, CommentCreate body) =>
{
    if (string.IsNullOrWhiteSpace(body.Author) || string.IsNullOrWhiteSpace(body.Content))
        return Results.BadRequest(new { message = "Author și Content sunt obligatorii" });
    var exists = await db.Posts.AnyAsync(p => p.Id == postId);
    if (!exists) return Results.NotFound();
    var c = new Comment { PostId = postId, Author = body.Author.Trim(), Content = body.Content, CreatedAt = DateTime.UtcNow };
    db.Comments.Add(c);
    await db.SaveChangesAsync();
    return Results.Created($"/api/comments/{c.Id}", new { c.Id });
}).WithName("CreateComment");

api.MapDelete("/comments/{id:int}", async (BlogDbContext db, int id) =>
{
    var c = await db.Comments.FindAsync(id);
    if (c is null) return Results.NotFound();
    db.Comments.Remove(c);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).WithName("DeleteComment");

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

// Группа: Session Handling Flaw (демо cookie параметров)
var labSession = app.MapGroup("/lab/session");
labSession.MapGet("/set", (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    var options = new CookieOptions
    {
        HttpOnly = !svc.SessionHandlingFlaw, // уязвимо: HttpOnly=false
        Secure = !svc.SessionHandlingFlaw ? ctx.Request.IsHttps : false, // уязвимо: Secure=false
        SameSite = svc.SessionHandlingFlaw ? SameSiteMode.None : SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.Add(svc.SessionHandlingFlaw ? TimeSpan.FromDays(30) : TimeSpan.FromMinutes(20)),
        Path = "/"
    };
    ctx.Response.Cookies.Append("lab-session", Guid.NewGuid().ToString("N"), options);
    return Results.Ok(new { message = "Setat cookie 'lab-session'", insecure = svc.SessionHandlingFlaw });
}).WithName("LabSessionSet");

labSession.MapGet("/whoami", (HttpContext ctx) =>
{
    var has = ctx.Request.Cookies.TryGetValue("lab-session", out var val);
    return Results.Ok(new { session = has ? val : null, has });
}).WithName("LabSessionWhoAmI");

// Группа: Logic Flaw (ценообразование)
var labLogic = app.MapGroup("/lab/logic");
labLogic.MapPost("/checkout", async (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    using var sr = new StreamReader(ctx.Request.Body);
    var json = await sr.ReadToEndAsync();
    var dto = System.Text.Json.JsonSerializer.Deserialize<CheckoutDto>(json, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
              ?? new CheckoutDto(0m, 1, 0m);

    decimal unit = Math.Max(0, dto.UnitPrice);
    int qty = Math.Clamp(dto.Qty, 1, 1000);

    decimal subtotal;
    decimal discountPct;

    if (svc.LogicFlaw)
    {
        // Уязвимо: доверяем присланной скидке
        discountPct = Math.Clamp(dto.DiscountPct, 0, 100);
        subtotal = unit * qty;
    }
    else
    {
        // Безопасно: игнорируем клиентскую скидку, считаем на сервере по правилам
        subtotal = unit * qty;
        discountPct = subtotal > 500 ? 10 : (subtotal > 100 ? 5 : 0);
    }

    var discount = subtotal * (discountPct / 100m);
    var total = subtotal - discount;
    return Results.Ok(new { subtotal, discountPct, discount, total });
}).WithName("LabLogicCheckout");

// Группа: AuthN/AuthZ (упрощенная демонстрация)
var labAuth = app.MapGroup("/lab/auth");
labAuth.MapPost("/login", async (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    string body; using (var sr = new StreamReader(ctx.Request.Body)) body = await sr.ReadToEndAsync();
    var form = System.Web.HttpUtility.ParseQueryString(body);
    var user = form["user"] ?? "";
    var pass = form["pass"] ?? "";

    bool ok;
    bool isAdmin;
    if (svc.AuthenticationBypass)
    {
        // Уязвимо: вход без пароля
        ok = !string.IsNullOrWhiteSpace(user);
        isAdmin = string.Equals(user, "admin", StringComparison.OrdinalIgnoreCase);
    }
    else
    {
        ok = user == "admin" && pass == "P@ssw0rd!";
        isAdmin = ok;
    }
    if (!ok) return Results.BadRequest(new { message = "Autentificare eșuată" });

    ctx.Response.Cookies.Append("lab-user", user, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Path = "/" });
    ctx.Response.Cookies.Append("lab-role", isAdmin ? "Admin" : "User", new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Path = "/" });
    return Results.Ok(new { message = "Autentificat", user, role = isAdmin ? "Admin" : "User" });
}).WithName("LabAuthLogin");

labAuth.MapPost("/logout", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("lab-user");
    ctx.Response.Cookies.Delete("lab-role");
    return Results.Ok(new { message = "Delogat" });
}).WithName("LabAuthLogout");

labAuth.MapGet("/me", (HttpContext ctx) =>
{
    ctx.Request.Cookies.TryGetValue("lab-user", out var user);
    ctx.Request.Cookies.TryGetValue("lab-role", out var role);
    return Results.Ok(new { user = user ?? "(anonim)", role = role ?? "(none)" });
}).WithName("LabAuthMe");

labAuth.MapGet("/admin", (HttpContext ctx) =>
{
    var svc = ctx.RequestServices.GetRequiredService<VulnerabilityToggleService>();
    var isBypass = svc.AuthorizationBypass;
    if (!isBypass)
    {
        var ok = ctx.Request.Cookies.TryGetValue("lab-role", out var role) && role == "Admin";
        if (!ok) return Results.StatusCode(403);
    }
    return Results.Ok(new { secret = "FLAG{zona_admin}", note = isBypass ? "(Vulnerabil: fără verificare)" : "(Securizat: verificare rol)" });
}).WithName("LabAuthAdmin");

// Поисковый эндпоинт для SQLi автотестов
app.MapGet("/lab/sqli/search", async (BlogDbContext db, VulnerabilityToggleService svc, string q) =>
{
    if (string.IsNullOrWhiteSpace(q)) return Results.Ok(Array.Empty<int>());
    if (svc.SqlInjection)
    {
        var sql = $"SELECT * FROM Posts WHERE Title LIKE '%{q.Replace("'", "''")}%' OR Content LIKE '%{q.Replace("'", "''")}%' ORDER BY CreatedAt DESC";
        var ids = await db.Posts.FromSqlRaw(sql).Select(p => p.Id).ToListAsync();
        return Results.Ok(ids);
    }
    else
    {
        var term = q.Trim();
        var ids = await db.Posts
            .Where(p => EF.Functions.Like(p.Title, $"%{term}%") || EF.Functions.Like(p.Content, $"%{term}%"))
            .OrderByDescending(p => p.CreatedAt)
            .Select(p => p.Id)
            .ToListAsync();
        return Results.Ok(ids);
    }
}).WithName("LabSqliSearch");

app.Run();

public record CommentCreate(string Author, string Content);
public record CheckoutDto(decimal UnitPrice, int Qty, decimal DiscountPct);
