using CyTypes.EntityFramework;
using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.Sample.WebApi;

public class SecureUser
{
    public int Id { get; set; }
    public CyString Name { get; set; } = null!;
    public CyString Email { get; set; } = null!;
    public CyInt Age { get; set; } = null!;
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<SecureUser> Users => Set<SecureUser>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // Registers value converters for all 10 CyTypes in one call
        configurationBuilder.UseCyTypes();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SecureUser>(entity =>
        {
            entity.HasKey(e => e.Id);
        });
    }
}
