using BenchmarkDotNet.Attributes;
using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.Benchmarks.Application.EfCore;

[MemoryDiagnoser]
public class EfCoreBenchmarks : IDisposable
{
    private BenchmarkDbContext _context = null!;

    [GlobalSetup]
    public void Setup()
    {
        var options = new DbContextOptionsBuilder<BenchmarkDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _context = new BenchmarkDbContext(options);
        _context.Database.OpenConnection();
        _context.Database.EnsureCreated();
    }

    [GlobalCleanup]
    public void Cleanup() => Dispose();

    public void Dispose()
    {
        _context?.Database.CloseConnection();
        _context?.Dispose();
        GC.SuppressFinalize(this);
    }

    [IterationSetup]
    public void IterationSetup()
    {
        _context.EncryptedOrders.ExecuteDelete();
        _context.PlainOrders.ExecuteDelete();
    }

    [Benchmark]
    public void InsertSingle_Encrypted()
    {
        _context.EncryptedOrders.Add(new EncryptedOrder
        {
            Name = new CyString("Test Order"),
            Quantity = new CyInt(10),
            Price = new CyDecimal(29.99m),
            OrderDate = new CyDateTime(DateTime.UtcNow)
        });
        _context.SaveChanges();
    }

    [Benchmark(Baseline = true)]
    public void InsertSingle_Plain()
    {
        _context.PlainOrders.Add(new PlainOrder
        {
            Name = "Test Order",
            Quantity = 10,
            Price = 29.99m,
            OrderDate = DateTime.UtcNow
        });
        _context.SaveChanges();
    }

    [Benchmark]
    public void InsertBulk100_Encrypted()
    {
        for (int i = 0; i < 100; i++)
        {
            _context.EncryptedOrders.Add(new EncryptedOrder
            {
                Name = new CyString($"Order {i}"),
                Quantity = new CyInt(i),
                Price = new CyDecimal(i * 10.5m),
                OrderDate = new CyDateTime(DateTime.UtcNow)
            });
        }
        _context.SaveChanges();
    }

    [Benchmark]
    public void InsertBulk100_Plain()
    {
        for (int i = 0; i < 100; i++)
        {
            _context.PlainOrders.Add(new PlainOrder
            {
                Name = $"Order {i}",
                Quantity = i,
                Price = i * 10.5m,
                OrderDate = DateTime.UtcNow
            });
        }
        _context.SaveChanges();
    }
}
