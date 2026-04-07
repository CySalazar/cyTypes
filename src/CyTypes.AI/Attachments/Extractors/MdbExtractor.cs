using System.Data.Odbc;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .mdb (Microsoft Access) extractor — uses System.Data.Odbc against the
/// <c>mdbtools</c> ODBC driver. Requires <c>mdbtools</c> + <c>unixodbc</c>
/// system packages on Linux. The extractor probes for the driver at runtime
/// and returns a clear error if it's missing.
/// </summary>
public sealed class MdbExtractor : DatabaseExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".mdb" };
    public override string Format => "mdb";

    protected override IEnumerable<(string table, string column, string value)> EnumerateStringValues(
        Stream stream, string fileName, CancellationToken ct)
    {
        // Need a path for ODBC.
        string path;
        string? tempPath = null;
        if (stream is FileStream fs) path = fs.Name;
        else
        {
            tempPath = Path.Combine(Path.GetTempPath(), $"mdb-{Guid.NewGuid():N}.mdb");
            using (var temp = File.Create(tempPath))
            {
                stream.Position = 0;
                stream.CopyTo(temp);
            }
            path = tempPath;
        }

        OdbcConnection? conn = null;
        try
        {
            // mdbtools driver name varies; try the common ones in order.
            string[] driverNames = { "MDBTools", "MDBToolsODBC", "Microsoft Access Driver (*.mdb)" };
            Exception? lastError = null;
            foreach (var driver in driverNames)
            {
                try
                {
                    conn = new OdbcConnection($"Driver={{{driver}}};DBQ={path}");
                    conn.Open();
                    break;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    conn?.Dispose();
                    conn = null;
                }
            }
            if (conn is null)
                throw new InvalidOperationException(
                    $"No suitable ODBC driver for .mdb found. Install 'mdbtools' + 'unixodbc' on Linux. Last error: {lastError?.Message}");

            var schema = conn.GetSchema("Tables");
            var tables = new List<string>();
            foreach (System.Data.DataRow row in schema.Rows)
            {
                var name = row["TABLE_NAME"]?.ToString();
                var type = row["TABLE_TYPE"]?.ToString();
                if (!string.IsNullOrEmpty(name) && type == "TABLE") tables.Add(name);
            }

            foreach (var table in tables)
            {
                ct.ThrowIfCancellationRequested();
                List<(string column, string value)> rows;
                try { rows = ReadTable(conn, table); }
                catch { continue; }
                foreach (var (col, val) in rows)
                    yield return (table, col, val);
            }
        }
        finally
        {
            conn?.Dispose();
            if (tempPath is not null && File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    private static List<(string column, string value)> ReadTable(OdbcConnection conn, string table)
    {
        var output = new List<(string, string)>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT * FROM [{table}]";
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
        {
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
