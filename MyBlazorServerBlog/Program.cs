using Microsoft.EntityFrameworkCore;
using System.Globalization;
using MyBlazorServerBlog.Data;
using MyBlazorServerBlog.Models;
using Syncfusion.Blazor;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
// Syncfusion Blazor
builder.Services.AddSyncfusionBlazor();

// EF Core + SQLite
builder.Services.AddDbContext<BlogDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

var app = builder.Build();


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

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

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

app.Run();

public record CommentCreate(string Author, string Content);
