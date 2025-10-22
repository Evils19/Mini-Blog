using System.ComponentModel.DataAnnotations;

namespace MyBlazorServerBlog.Models;

public class Post
{
    public int Id { get; set; }

    [Required]
    [StringLength(200)]
    public string Title { get; set; } = string.Empty;

    [Required]
    public string Content { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public bool IsPublished { get; set; } = true;

    // Связь с комментариями
    public List<Comment> Comments { get; set; } = new();

    public byte[]? ImageData { get; set; }
}
