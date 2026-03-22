using System.Diagnostics.CodeAnalysis;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.Benchmarks.Application.EfCore;

[MemoryDiagnoser]
[SuppressMessage("Reliability", "CA1001:Types that own disposable fields should be disposable")]
public class EfCoreBenchmarks
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
    public void Cleanup()
    {
        _context?.Database.CloseConnection();
        _context?.Dispose();
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
            Name = new CyString("Test Order", SecurityPolicy.Performance),
            Quantity = new CyInt(10, SecurityPolicy.Performance),
            Price = new CyDecimal(29.99m, SecurityPolicy.Performance),
            OrderDate = new CyDateTime(DateTime.UtcNow, SecurityPolicy.Performance)
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
                Name = new CyString($"Order {i}", SecurityPolicy.Performance),
                Quantity = new CyInt(i, SecurityPolicy.Performance),
                Price = new CyDecimal(i * 10.5m, SecurityPolicy.Performance),
                OrderDate = new CyDateTime(DateTime.UtcNow, SecurityPolicy.Performance)
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
