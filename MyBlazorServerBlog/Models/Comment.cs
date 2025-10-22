using System;
using System.ComponentModel.DataAnnotations;

namespace MyBlazorServerBlog.Models
{
    public class Comment
    {
        public int Id { get; set; }
        public int PostId { get; set; }
        [Required]
        [StringLength(100)]
        public string Author { get; set; } = string.Empty;
        [Required]
        [StringLength(1000)]
        public string Content { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Навигационное свойство для Post
        public Post? Post { get; set; }
    }
}
