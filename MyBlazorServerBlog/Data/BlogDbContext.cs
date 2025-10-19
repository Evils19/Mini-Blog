using Microsoft.EntityFrameworkCore;
using MyBlazorServerBlog.Models;

namespace MyBlazorServerBlog.Data;

public class BlogDbContext : DbContext
{
    public BlogDbContext(DbContextOptions<BlogDbContext> options) : base(options)
    {
    }

    public DbSet<Post> Posts => Set<Post>();
}
