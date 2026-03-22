namespace CyTypes.StressTests.Infrastructure;

/// <summary>
/// Centralized configuration for stress tests. All values can be overridden via environment variables.
/// </summary>
public static class StressTestConfig
{
    public static readonly int ConcurrentThreads = GetEnvInt("STRESS_THREADS", 100);
    public static readonly int IterationsPerThread = GetEnvInt("STRESS_ITERATIONS", 1000);
    public static readonly int SoakDurationSeconds = GetEnvInt("STRESS_SOAK_SECONDS", 30);
    public static readonly int MaxPayloadBytes = 16 * 1024 * 1024; // 16 MB
    public static readonly int SecureBufferAllocCount = GetEnvInt("STRESS_BUFFER_COUNT", 5000);
    public static readonly int NetworkConnectionCount = GetEnvInt("STRESS_NET_CONNECTIONS", 50);
    public static readonly int BulkEntityCount = GetEnvInt("STRESS_BULK_ENTITIES", 1000);
    public static readonly int FheOperationChainLength = GetEnvInt("STRESS_FHE_CHAIN", 20);
    public static readonly int TimeoutSeconds = GetEnvInt("STRESS_TIMEOUT", 120);

    public static TimeSpan SoakDuration => TimeSpan.FromSeconds(SoakDurationSeconds);
    public static TimeSpan Timeout => TimeSpan.FromSeconds(TimeoutSeconds);

    private static int GetEnvInt(string name, int defaultValue)
    {
        var val = Environment.GetEnvironmentVariable(name);
        return int.TryParse(val, out var result) ? result : defaultValue;
    }
}
