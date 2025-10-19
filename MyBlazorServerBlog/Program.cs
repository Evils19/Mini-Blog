using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using MyBlazorServerBlog.Data;
using MyBlazorServerBlog.Models;
using Syncfusion.Blazor;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
// Syncfusion Blazor
builder.Services.AddSyncfusionBlazor();

// EF Core + SQLite
builder.Services.AddDbContext<BlogDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

var app = builder.Build();

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

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
