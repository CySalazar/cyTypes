// CyTypes.Sample.WebApi — Minimal API with encrypted entities, DI, and redacting logger.
//
// Run:  dotnet run --project examples/CyTypes.Sample.WebApi
// Test: curl -X POST http://localhost:5000/users -H "Content-Type: application/json" \
//         -d '{"name":"Alice","email":"alice@example.com","age":30}'
//       curl http://localhost:5000/users

using CyTypes.Core.Policy;
using CyTypes.DependencyInjection;
using CyTypes.EntityFramework;
using CyTypes.Primitives;
using CyTypes.Sample.WebApi;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// --- Register cyTypes with DI ---
builder.Services.AddSingleton<ILogger>(sp =>
    sp.GetRequiredService<ILoggerFactory>().CreateLogger("CyTypes"));
builder.Services.AddCyTypes(options =>
{
    options.DefaultPolicy = SecurityPolicy.Balanced;
    options.EnableRedactingLogger = true;
});

// --- SQLite in-memory (shared connection kept open) ---
var connection = new SqliteConnection("Data Source=:memory:");
connection.Open();
builder.Services.AddSingleton(connection);
builder.Services.AddDbContext<AppDbContext>((sp, opt) =>
    opt.UseSqlite(sp.GetRequiredService<SqliteConnection>()));

var app = builder.Build();

// Ensure DB created
using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
}

// --- Endpoints ---

app.MapGet("/users", async (AppDbContext db) =>
{
    var users = await db.Users.ToListAsync();
    var result = users.Select(u => new
    {
        u.Id,
        Name = u.Name.ToInsecureString(),
        Email = u.Email.ToInsecureString(),
        Age = u.Age.ToInsecureInt()
    });
    return Results.Ok(result);
});

app.MapGet("/users/{id:int}", async (int id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    return Results.Ok(new
    {
        user.Id,
        Name = user.Name.ToInsecureString(),
        Email = user.Email.ToInsecureString(),
        Age = user.Age.ToInsecureInt()
    });
});

app.MapPost("/users", async (CreateUserRequest req, AppDbContext db, ILogger<Program> logger) =>
{
    var user = new SecureUser
    {
        Name = new CyString(req.Name),
        Email = new CyString(req.Email),
        Age = new CyInt(req.Age)
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    // Log with redaction — encrypted metadata is stripped automatically
    logger.LogInformation("Created user {Id} with name {Name}", user.Id, user.Name);

    return Results.Created($"/users/{user.Id}", new { user.Id });
});

app.MapDelete("/users/{id:int}", async (int id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    db.Users.Remove(user);
    await db.SaveChangesAsync();

    user.Name.Dispose();
    user.Email.Dispose();
    user.Age.Dispose();

    return Results.NoContent();
});

Console.WriteLine();
Console.WriteLine("  CyTypes Sample WebAPI running on http://localhost:5000");
Console.WriteLine("  Try: curl http://localhost:5000/users");
Console.WriteLine("       curl -X POST http://localhost:5000/users \\");
Console.WriteLine("         -H 'Content-Type: application/json' \\");
Console.WriteLine("         -d '{\"name\":\"Alice\",\"email\":\"alice@example.com\",\"age\":30}'");
Console.WriteLine();

app.Run("http://localhost:5000");

// --- Request DTO ---
sealed record CreateUserRequest(string Name, string Email, int Age);
