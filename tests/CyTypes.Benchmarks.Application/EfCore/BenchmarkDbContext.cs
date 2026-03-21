using CyTypes.EntityFramework;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.Benchmarks.Application.EfCore;

public class BenchmarkDbContext : DbContext
{
    public DbSet<EncryptedOrder> EncryptedOrders { get; set; } = null!;
    public DbSet<PlainOrder> PlainOrders { get; set; } = null!;

    public BenchmarkDbContext(DbContextOptions<BenchmarkDbContext> options) : base(options) { }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.UseCyTypes();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<EncryptedOrder>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<PlainOrder>(entity =>
        {
            entity.HasKey(e => e.Id);
        });
    }
}
