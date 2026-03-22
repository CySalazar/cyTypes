using System.Collections.Concurrent;
using CyTypes.Core.Policy;
using CyTypes.EntityFramework;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
public class EfCoreBulkStressTests
{
    private readonly ITestOutputHelper _output;

    public EfCoreBulkStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private sealed class TestEntity
    {
        public int Id { get; set; }
        public CyString Name { get; set; } = null!;
        public CyInt Score { get; set; } = null!;
    }

    private sealed class TestDbContext : DbContext
    {
        public DbSet<TestEntity> Entities => Set<TestEntity>();

        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
        {
            configurationBuilder.UseCyTypes();
        }
    }

    private static DbContextOptions<TestDbContext> CreateOptions()
    {
        return new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
    }

    [Fact]
    public async Task BulkInsert_And_ReadBack()
    {
        // Arrange
        var count = StressTestConfig.BulkEntityCount;
        var policy = SecurityPolicy.Performance;
        var options = CreateOptions();
        var counter = new ThroughputCounter();

        using var db = new TestDbContext(options);
        db.Database.OpenConnection();
        db.Database.EnsureCreated();

        var expectedValues = new Dictionary<int, (string Name, int Score)>();

        // Act: Bulk insert
        for (var i = 0; i < count; i++)
        {
            var name = $"entity-{i}";
            var score = i * 10;
            expectedValues[i + 1] = (name, score); // EF Core auto-increments from 1

            db.Entities.Add(new TestEntity
            {
                Name = new CyString(name, policy),
                Score = new CyInt(score, policy)
            });
            counter.Increment();
        }

        await db.SaveChangesAsync();

        // Act: Read back all entities
        var entities = await db.Entities.ToListAsync();

        // Assert
        entities.Should().HaveCount(count, "all entities should be persisted");

        foreach (var entity in entities)
        {
            expectedValues.Should().ContainKey(entity.Id);
            var (expectedName, expectedScore) = expectedValues[entity.Id];
            entity.Name.ToInsecureString().Should().Be(expectedName);
            entity.Score.ToInsecureInt().Should().Be(expectedScore);
        }

        _output.WriteLine($"Bulk insert and read-back of {count} entities: {counter.Summary}");
    }

    [Fact]
    public async Task ConcurrentInsertAndRead()
    {
        // Arrange
        var policy = SecurityPolicy.Performance;
        var options = CreateOptions();
        var exceptions = new ConcurrentBag<Exception>();
        const int insertCount = 200;
        var insertedIds = new ConcurrentBag<int>();

        // Create and initialize the database
        using (var setupDb = new TestDbContext(options))
        {
            setupDb.Database.OpenConnection();
            setupDb.Database.EnsureCreated();
        }

        // Note: SQLite in-memory requires sharing the same connection.
        // We use a single connection string with shared cache.
        var sharedOptions = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite("DataSource=ConcurrentTest;Mode=Memory;Cache=Shared")
            .Options;

        // Initialize with shared cache
        using var sharedDb = new TestDbContext(sharedOptions);
        sharedDb.Database.OpenConnection();
        sharedDb.Database.EnsureCreated();

        // Act: Writer task
        var writerTask = Task.Run(async () =>
        {
            try
            {
                using var writerDb = new TestDbContext(sharedOptions);
                writerDb.Database.OpenConnection();

                for (var i = 0; i < insertCount; i++)
                {
                    writerDb.Entities.Add(new TestEntity
                    {
                        Name = new CyString($"concurrent-{i}", policy),
                        Score = new CyInt(i, policy)
                    });
                    await writerDb.SaveChangesAsync();
                    insertedIds.Add(i);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Act: Reader task (reads periodically)
        var readerTask = Task.Run(async () =>
        {
            try
            {
                using var readerDb = new TestDbContext(sharedOptions);
                readerDb.Database.OpenConnection();

                for (var attempt = 0; attempt < 50; attempt++)
                {
                    var entities = await readerDb.Entities.AsNoTracking().ToListAsync();
                    // Verify each read entity has valid decryptable data
                    foreach (var entity in entities)
                    {
                        var name = entity.Name.ToInsecureString();
                        name.Should().StartWith("concurrent-");
                        var score = entity.Score.ToInsecureInt();
                        score.Should().BeGreaterOrEqualTo(0);
                    }

                    await Task.Delay(10);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        await Task.WhenAll(writerTask, readerTask);

        // Assert
        exceptions.Should().BeEmpty("concurrent insert and read should not cause corruption");
        insertedIds.Should().HaveCount(insertCount);

        _output.WriteLine($"Concurrent insert ({insertCount} entities) and read completed without corruption");
    }
}
