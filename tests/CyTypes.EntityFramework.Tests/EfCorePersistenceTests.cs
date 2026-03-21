using CyTypes.EntityFramework;
using CyTypes.Primitives;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CyTypes.EntityFramework.Tests;

public sealed class EfCorePersistenceTests : IDisposable
{
    private sealed class TestEntity
    {
        public int Id { get; set; }
        public CyString Name { get; set; } = null!;
        public CyInt Score { get; set; } = null!;
        public CyBool IsActive { get; set; } = null!;
        public CyDouble Rating { get; set; } = null!;
        public CyGuid ExternalId { get; set; } = null!;
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

    private readonly TestDbContext _db;

    public EfCorePersistenceTests()
    {
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
        _db = new TestDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyString()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 1,
            Name = new CyString("Alice"),
            Score = new CyInt(100),
            IsActive = new CyBool(true),
            Rating = new CyDouble(4.5),
            ExternalId = new CyGuid(Guid.Empty)
        });
        _db.SaveChanges();

        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 1);
        loaded.Name.ToInsecureString().Should().Be("Alice");
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyInt()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 2,
            Name = new CyString("Bob"),
            Score = new CyInt(250),
            IsActive = new CyBool(false),
            Rating = new CyDouble(3.2),
            ExternalId = new CyGuid(Guid.NewGuid())
        });
        _db.SaveChanges();

        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 2);
        loaded.Score.ToInsecureInt().Should().Be(250);
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyBool()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 3,
            Name = new CyString("Charlie"),
            Score = new CyInt(0),
            IsActive = new CyBool(true),
            Rating = new CyDouble(0),
            ExternalId = new CyGuid(Guid.Empty)
        });
        _db.SaveChanges();

        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 3);
        loaded.IsActive.ToInsecureBool().Should().BeTrue();
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyDouble()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 4,
            Name = new CyString("test"),
            Score = new CyInt(0),
            IsActive = new CyBool(false),
            Rating = new CyDouble(9.81),
            ExternalId = new CyGuid(Guid.Empty)
        });
        _db.SaveChanges();

        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 4);
        loaded.Rating.ToInsecureDouble().Should().Be(9.81);
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyGuid()
    {
        var guid = Guid.NewGuid();
        _db.Entities.Add(new TestEntity
        {
            Id = 5,
            Name = new CyString("test"),
            Score = new CyInt(0),
            IsActive = new CyBool(false),
            Rating = new CyDouble(0),
            ExternalId = new CyGuid(guid)
        });
        _db.SaveChanges();

        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 5);
        loaded.ExternalId.ToInsecureGuid().Should().Be(guid);
    }

    [Fact]
    public void Update_persisted_entity_round_trips()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 6,
            Name = new CyString("original"),
            Score = new CyInt(10),
            IsActive = new CyBool(true),
            Rating = new CyDouble(1.0),
            ExternalId = new CyGuid(Guid.Empty)
        });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var entity = _db.Entities.Single(e => e.Id == 6);
        entity.Name = new CyString("updated");
        entity.Score = new CyInt(20);
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var reloaded = _db.Entities.Single(e => e.Id == 6);
        reloaded.Name.ToInsecureString().Should().Be("updated");
        reloaded.Score.ToInsecureInt().Should().Be(20);
    }

    [Fact]
    public void Delete_persisted_entity_removes_it()
    {
        _db.Entities.Add(new TestEntity
        {
            Id = 7,
            Name = new CyString("toDelete"),
            Score = new CyInt(0),
            IsActive = new CyBool(false),
            Rating = new CyDouble(0),
            ExternalId = new CyGuid(Guid.Empty)
        });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var entity = _db.Entities.Single(e => e.Id == 7);
        _db.Entities.Remove(entity);
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        _db.Entities.Any(e => e.Id == 7).Should().BeFalse();
    }

    [Fact]
    public void Multiple_entities_round_trip()
    {
        _db.Entities.AddRange(
            new TestEntity { Id = 8, Name = new CyString("a"), Score = new CyInt(1), IsActive = new CyBool(true), Rating = new CyDouble(1.0), ExternalId = new CyGuid(Guid.Empty) },
            new TestEntity { Id = 9, Name = new CyString("b"), Score = new CyInt(2), IsActive = new CyBool(false), Rating = new CyDouble(2.0), ExternalId = new CyGuid(Guid.Empty) }
        );
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var entities = _db.Entities.Where(e => e.Id >= 8 && e.Id <= 9).OrderBy(e => e.Id).ToList();
        entities.Should().HaveCount(2);
        entities[0].Name.ToInsecureString().Should().Be("a");
        entities[1].Name.ToInsecureString().Should().Be("b");
    }

    public void Dispose()
    {
        _db.Database.CloseConnection();
        _db.Dispose();
    }
}
