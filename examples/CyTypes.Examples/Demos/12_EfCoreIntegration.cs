using CyTypes.EntityFramework;
using CyTypes.EntityFramework.Converters;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.Examples.Demos;

public static class EfCoreIntegration
{
    // --- Sample entity with encrypted properties ---
    private sealed class SecureUser
    {
        public int Id { get; set; }
        public CyString Name { get; set; } = null!;
        public CyString Email { get; set; } = null!;
        public CyInt Age { get; set; } = null!;
    }

    // --- DbContext with CyTypes value converters ---
    private sealed class AppDbContext : DbContext
    {
        private readonly SqliteConnection _connection;

        public AppDbContext(SqliteConnection connection)
        {
            _connection = connection;
        }

        public DbSet<SecureUser> Users => Set<SecureUser>();

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // Use the shared in-memory connection so data persists across operations
            options.UseSqlite(_connection);
        }

        protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
        {
            // Register all CyTypes value converters in one call
            configurationBuilder.UseCyTypes();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<SecureUser>(entity =>
            {
                entity.HasKey(e => e.Id);

                // CyString/CyInt properties are handled automatically by
                // the converters registered in ConfigureConventions above.
                // EF Core calls ToInsecureString()/ToInsecureInt() on save,
                // and re-encrypts via new CyString()/new CyInt() on load.
            });
        }
    }

    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 12: EF Core Integration - Encrypted Entities");

        ConsoleHelpers.PrintNote("CyTypes.EntityFramework provides value converters so EF Core can");
        ConsoleHelpers.PrintNote("persist CyString, CyInt, etc. Data is decrypted only at the DB boundary.");
        Console.WriteLine();

        // --- Define an entity ---
        ConsoleHelpers.PrintSubHeader("Step 1: Define an Entity with CyType Properties");
        ConsoleHelpers.PrintCode("public class SecureUser");
        ConsoleHelpers.PrintCode("{");
        ConsoleHelpers.PrintCode("    public int Id { get; set; }");
        ConsoleHelpers.PrintCode("    public CyString Name { get; set; }");
        ConsoleHelpers.PrintCode("    public CyString Email { get; set; }");
        ConsoleHelpers.PrintCode("    public CyInt Age { get; set; }");
        ConsoleHelpers.PrintCode("}");
        Console.WriteLine();

        // --- Configure converters ---
        ConsoleHelpers.PrintSubHeader("Step 2: Register Value Converters");
        ConsoleHelpers.PrintCode("protected override void ConfigureConventions(ModelConfigurationBuilder cb)");
        ConsoleHelpers.PrintCode("{");
        ConsoleHelpers.PrintCode("    cb.UseCyTypes();  // registers converters for all 10 types");
        ConsoleHelpers.PrintCode("}");
        ConsoleHelpers.PrintNote("UseCyTypes() registers CyIntValueConverter, CyStringValueConverter, etc.");
        ConsoleHelpers.PrintNote("You can also register individual converters if you prefer.");
        Console.WriteLine();

        // --- Save and load encrypted data ---
        ConsoleHelpers.PrintSubHeader("Step 3: Save and Load Encrypted Data");

        // Sqlite in-memory DB requires a kept-open connection
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using var db = new AppDbContext(connection);
        db.Database.EnsureCreated();

        // Create an entity with encrypted properties
        using var name = new CyString("Alice");
        using var email = new CyString("alice@example.com");
        using var age = new CyInt(30);

        var user = new SecureUser
        {
            Id = 1,
            Name = name,
            Email = email,
            Age = age,
        };

        ConsoleHelpers.PrintCode("var user = new SecureUser { Name = new CyString(\"Alice\"), ... };");
        ConsoleHelpers.PrintCode("db.Users.Add(user);");
        ConsoleHelpers.PrintCode("db.SaveChanges();");

        db.Users.Add(user);
        db.SaveChanges();

        ConsoleHelpers.PrintSecure("Entity saved. CyString/CyInt decrypted at the DB boundary only.");
        Console.WriteLine();

        // Detach and reload
        db.ChangeTracker.Clear();

        ConsoleHelpers.PrintCode("var loaded = db.Users.Find(1);");
        var loaded = db.Users.Find(1);

        ConsoleHelpers.PrintInfo($"loaded.Name (ToString): {loaded!.Name}");
        ConsoleHelpers.PrintNote("ToString() is redacted — the value is re-encrypted in memory on load.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("loaded.Name.ToInsecureString()");
        ConsoleHelpers.PrintRisk($"=> {loaded.Name.ToInsecureString()}, IsCompromised = {loaded.Name.IsCompromised}");
        ConsoleHelpers.PrintCode("loaded.Age.ToInsecureInt()");
        ConsoleHelpers.PrintRisk($"=> {loaded.Age.ToInsecureInt()}, IsCompromised = {loaded.Age.IsCompromised}");
        Console.WriteLine();

        // --- Individual converter usage ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Individual Converter Registration (Alternative)");
        ConsoleHelpers.PrintCode("configurationBuilder.Properties<CyString>()");
        ConsoleHelpers.PrintCode("    .HaveConversion<CyStringValueConverter>();");
        ConsoleHelpers.PrintCode("configurationBuilder.Properties<CyInt>()");
        ConsoleHelpers.PrintCode("    .HaveConversion<CyIntValueConverter>();");
        ConsoleHelpers.PrintNote("Use this pattern when you only need converters for specific CyTypes.");

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("Key takeaway: EF Core stores plaintext in the DB; CyTypes keep it encrypted in app memory.");

        // Cleanup
        loaded.Name.Dispose();
        loaded.Email.Dispose();
        loaded.Age.Dispose();
        db.Database.EnsureDeleted();
    }
}
