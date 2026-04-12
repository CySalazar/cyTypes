namespace CyTypes.Core.Security;

/// <summary>Exception thrown when the decryption rate limit is exceeded for a CyType instance.</summary>
public sealed class RateLimitExceededException : Exception
{
    /// <summary>The maximum number of decryptions allowed per window.</summary>
    public int Limit { get; }
    /// <summary>The unique identifier of the instance that exceeded its rate limit.</summary>
    public Guid InstanceId { get; }
    /// <summary>The sliding window duration for the rate limit.</summary>
    public TimeSpan Window { get; }

    /// <summary>Initializes a new instance of <see cref="RateLimitExceededException"/> with the offending instance, limit, and window.</summary>
    public RateLimitExceededException(Guid instanceId, int limit, TimeSpan window)
        : base($"Decryption rate limit exceeded for instance {instanceId}. Limit: {limit}/{window.TotalSeconds:F1}s.")
    {
        InstanceId = instanceId;
        Limit = limit;
        Window = window;
    }

    /// <summary>Initializes a new instance with default 1-second window for backward compatibility.</summary>
    public RateLimitExceededException(Guid instanceId, int limit)
        : this(instanceId, limit, TimeSpan.FromSeconds(1))
    {
    }
}
