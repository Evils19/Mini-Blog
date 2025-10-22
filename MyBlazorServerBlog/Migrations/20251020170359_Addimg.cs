using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MyBlazorServerBlog.Migrations
{
    /// <inheritdoc />
    public partial class Addimg : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "ImageData",
                table: "Posts",
                type: "BLOB",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ImageData",
                table: "Posts");
        }
    }
}
