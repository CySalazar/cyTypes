namespace CyTypes.Core.KeyManagement;

/// <summary>
/// Exception thrown when an encryption key has exceeded its time-to-live.
/// </summary>
public sealed class KeyExpiredException : Exception
{
    /// <summary>
    /// Gets the unique identifier of the expired key.
    /// </summary>
    public Guid KeyId { get; }

    /// <summary>
    /// Gets the age of the key at the time of expiration check.
    /// </summary>
    public TimeSpan Age { get; }

    /// <summary>
    /// Gets the configured time-to-live for the key.
    /// </summary>
    public TimeSpan Ttl { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyExpiredException"/> class.
    /// </summary>
    /// <param name="keyId">The unique identifier of the expired key.</param>
    /// <param name="age">The age of the key.</param>
    /// <param name="ttl">The configured time-to-live.</param>
    public KeyExpiredException(Guid keyId, TimeSpan age, TimeSpan ttl)
        : base("Encryption key has expired. Rotate or create a new key.")
    {
        KeyId = keyId;
        Age = age;
        Ttl = ttl;
    }
}
