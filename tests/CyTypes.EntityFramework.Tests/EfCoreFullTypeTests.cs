using CyTypes.EntityFramework;
using CyTypes.Primitives;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CyTypes.EntityFramework.Tests;

/// <summary>Tests persistence for all 10 CyType primitive types through EF Core.</summary>
public sealed class EfCoreFullTypeTests : IDisposable
{
    private sealed class FullTypeEntity
    {
        public int Id { get; set; }
        public CyString StringVal { get; set; } = null!;
        public CyInt IntVal { get; set; } = null!;
        public CyLong LongVal { get; set; } = null!;
        public CyFloat FloatVal { get; set; } = null!;
        public CyDouble DoubleVal { get; set; } = null!;
        public CyDecimal DecimalVal { get; set; } = null!;
        public CyBool BoolVal { get; set; } = null!;
        public CyGuid GuidVal { get; set; } = null!;
        public CyDateTime DateTimeVal { get; set; } = null!;
        public CyBytes BytesVal { get; set; } = null!;
    }

    private sealed class FullTypeDbContext : DbContext
    {
        public DbSet<FullTypeEntity> Entities => Set<FullTypeEntity>();

        public FullTypeDbContext(DbContextOptions<FullTypeDbContext> options) : base(options) { }

        protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
        {
            configurationBuilder.UseCyTypes();
        }
    }

    private readonly FullTypeDbContext _db;

    public EfCoreFullTypeTests()
    {
        var options = new DbContextOptionsBuilder<FullTypeDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
        _db = new FullTypeDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();
    }

    private static FullTypeEntity CreateEntity(int id) => new()
    {
        Id = id,
        StringVal = new CyString("test"),
        IntVal = new CyInt(42),
        LongVal = new CyLong(9_876_543_210L),
        FloatVal = new CyFloat(3.14f),
        DoubleVal = new CyDouble(2.71828),
        DecimalVal = new CyDecimal(19.99m),
        BoolVal = new CyBool(true),
        GuidVal = new CyGuid(Guid.Parse("12345678-1234-1234-1234-123456789abc")),
        DateTimeVal = new CyDateTime(new DateTime(2026, 3, 22, 12, 0, 0, DateTimeKind.Utc)),
        BytesVal = new CyBytes(new byte[] { 1, 2, 3, 4, 5 }),
    };

    [Fact]
    public void Insert_and_read_back_preserves_CyLong()
    {
        _db.Entities.Add(CreateEntity(1));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 1);
        loaded.LongVal.ToInsecureLong().Should().Be(9_876_543_210L);
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyFloat()
    {
        _db.Entities.Add(CreateEntity(2));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 2);
        loaded.FloatVal.ToInsecureFloat().Should().BeApproximately(3.14f, 0.001f);
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyDecimal()
    {
        _db.Entities.Add(CreateEntity(3));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 3);
        loaded.DecimalVal.ToInsecureDecimal().Should().Be(19.99m);
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyDateTime()
    {
        _db.Entities.Add(CreateEntity(4));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 4);
        loaded.DateTimeVal.ToInsecureDateTime().Should().Be(new DateTime(2026, 3, 22, 12, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void Insert_and_read_back_preserves_CyBytes()
    {
        _db.Entities.Add(CreateEntity(5));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 5);
        loaded.BytesVal.ToInsecureBytes().Should().Equal(new byte[] { 1, 2, 3, 4, 5 });
    }

    [Fact]
    public void All_ten_types_round_trip_in_single_entity()
    {
        var guid = Guid.Parse("12345678-1234-1234-1234-123456789abc");
        var dt = new DateTime(2026, 3, 22, 12, 0, 0, DateTimeKind.Utc);

        _db.Entities.Add(CreateEntity(6));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 6);
        loaded.StringVal.ToInsecureString().Should().Be("test");
        loaded.IntVal.ToInsecureInt().Should().Be(42);
        loaded.LongVal.ToInsecureLong().Should().Be(9_876_543_210L);
        loaded.FloatVal.ToInsecureFloat().Should().BeApproximately(3.14f, 0.001f);
        loaded.DoubleVal.ToInsecureDouble().Should().Be(2.71828);
        loaded.DecimalVal.ToInsecureDecimal().Should().Be(19.99m);
        loaded.BoolVal.ToInsecureBool().Should().BeTrue();
        loaded.GuidVal.ToInsecureGuid().Should().Be(guid);
        loaded.DateTimeVal.ToInsecureDateTime().Should().Be(dt);
        loaded.BytesVal.ToInsecureBytes().Should().Equal(new byte[] { 1, 2, 3, 4, 5 });
    }

    [Fact]
    public async Task SaveChangesAsync_works()
    {
        _db.Entities.Add(CreateEntity(7));
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        var loaded = await _db.Entities.SingleAsync(e => e.Id == 7);
        loaded.IntVal.ToInsecureInt().Should().Be(42);
    }

    [Fact]
    public void Boundary_values_round_trip()
    {
        _db.Entities.Add(new FullTypeEntity
        {
            Id = 8,
            StringVal = new CyString(""),
            IntVal = new CyInt(int.MinValue),
            LongVal = new CyLong(long.MaxValue),
            FloatVal = new CyFloat(float.Epsilon),
            DoubleVal = new CyDouble(double.MinValue),
            DecimalVal = new CyDecimal(decimal.Zero),
            BoolVal = new CyBool(false),
            GuidVal = new CyGuid(Guid.Empty),
            DateTimeVal = new CyDateTime(DateTime.MinValue),
            BytesVal = new CyBytes(Array.Empty<byte>()),
        });
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var loaded = _db.Entities.Single(e => e.Id == 8);
        loaded.StringVal.ToInsecureString().Should().BeEmpty();
        loaded.IntVal.ToInsecureInt().Should().Be(int.MinValue);
        loaded.LongVal.ToInsecureLong().Should().Be(long.MaxValue);
        loaded.FloatVal.ToInsecureFloat().Should().Be(float.Epsilon);
        loaded.DoubleVal.ToInsecureDouble().Should().Be(double.MinValue);
        loaded.DecimalVal.ToInsecureDecimal().Should().Be(decimal.Zero);
        loaded.BoolVal.ToInsecureBool().Should().BeFalse();
        loaded.GuidVal.ToInsecureGuid().Should().Be(Guid.Empty);
        loaded.BytesVal.ToInsecureBytes().Should().BeEmpty();
    }

    [Fact]
    public void Update_all_types_round_trips()
    {
        _db.Entities.Add(CreateEntity(9));
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var entity = _db.Entities.Single(e => e.Id == 9);
        entity.StringVal = new CyString("updated");
        entity.IntVal = new CyInt(999);
        entity.LongVal = new CyLong(1L);
        entity.FloatVal = new CyFloat(0.1f);
        entity.DoubleVal = new CyDouble(0.001);
        entity.DecimalVal = new CyDecimal(0.01m);
        entity.BoolVal = new CyBool(false);
        _db.SaveChanges();
        _db.ChangeTracker.Clear();

        var reloaded = _db.Entities.Single(e => e.Id == 9);
        reloaded.StringVal.ToInsecureString().Should().Be("updated");
        reloaded.IntVal.ToInsecureInt().Should().Be(999);
        reloaded.LongVal.ToInsecureLong().Should().Be(1L);
        reloaded.BoolVal.ToInsecureBool().Should().BeFalse();
    }

    public void Dispose()
    {
        _db.Database.CloseConnection();
        _db.Dispose();
    }
}
