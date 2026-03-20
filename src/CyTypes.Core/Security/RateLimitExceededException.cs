namespace CyTypes.Core.Security;

/// <summary>Exception thrown when the decryption rate limit is exceeded for a CyType instance.</summary>
public sealed class RateLimitExceededException : Exception
{
    /// <summary>The maximum number of decryptions allowed per second.</summary>
    public int Limit { get; }
    /// <summary>The unique identifier of the instance that exceeded its rate limit.</summary>
    public Guid InstanceId { get; }

    /// <summary>Initializes a new instance of <see cref="RateLimitExceededException"/> with the offending instance and limit.</summary>
    public RateLimitExceededException(Guid instanceId, int limit)
        : base($"Decryption rate limit exceeded for instance {instanceId}. Limit: {limit}/sec.")
    {
        InstanceId = instanceId;
        Limit = limit;
    }
}
