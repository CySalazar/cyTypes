using Microsoft.Data.Sqlite;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .db / .sqlite extractor — opens the database via Microsoft.Data.Sqlite,
/// iterates every user table, dumps every column value as a string.
/// </summary>
public sealed class SqliteExtractor : DatabaseExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".db", ".sqlite" };
    public override string Format => "sqlite";

    protected override IEnumerable<(string table, string column, string value)> EnumerateStringValues(
        Stream stream, string fileName, CancellationToken ct)
    {
        // Sqlite needs a file path. If we don't already have one, dump the
        // stream into an atomic per-call SafeTempDir which gets nuked on Dispose.
        string path;
        SafeTempDir? safeDir = null;
        if (stream is FileStream fs) path = fs.Name;
        else
        {
            safeDir = new SafeTempDir("sqlite-");
            path = Path.Combine(safeDir.Path, "db.sqlite");
            using var temp = File.Create(path);
            stream.Position = 0;
            stream.CopyTo(temp);
        }

        SqliteConnection? conn = null;
        try
        {
            conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
            conn.Open();

            // List user tables (skip sqlite_ prefixed system tables)
            var tables = new List<string>();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
                using var rd = cmd.ExecuteReader();
                while (rd.Read()) tables.Add(rd.GetString(0));
            }

            foreach (var table in tables)
            {
                ct.ThrowIfCancellationRequested();
                List<(string column, string value)> rows;
                try { rows = ReadTable(conn, table, ct); }
                catch { continue; }
                foreach (var (col, val) in rows)
                    yield return (table, col, val);
            }
        }
        finally
        {
            conn?.Dispose();
            safeDir?.Dispose();
        }
    }

    private static List<(string column, string value)> ReadTable(SqliteConnection conn, string table, CancellationToken ct)
    {
        var output = new List<(string, string)>();
        using var cmd = conn.CreateCommand();
        // table identifier double-quoted to allow names with hyphens / spaces
        cmd.CommandText = $"SELECT * FROM \"{table.Replace("\"", "\"\"")}\"";
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
        {
            ct.ThrowIfCancellationRequested();
            for (int i = 0; i < rd.FieldCount; i++)
            {
                if (rd.IsDBNull(i)) continue;
                var col = rd.GetName(i);
                var val = rd.GetValue(i)?.ToString() ?? string.Empty;
                if (val.Length > 0) output.Add((col, val));
            }
        }
        return output;
    }
}
