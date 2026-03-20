namespace CyTypes.Core.Security;

/// <summary>Tracks security state for a CyType instance, including decryption counts, rate limiting, and compromise flags.</summary>
public sealed class SecurityContext
{
    private readonly int _maxDecryptionCount;
    private readonly int? _decryptionRateLimit;
    private int _decryptionCount;
    private int _operationCount;
    private readonly object _rateLimitLock = new();
    private readonly long[] _decryptionTimestamps;
    private int _timestampIndex;
    private int _timestampCount;

    private int _isCompromised;  // 0 = false, 1 = true (atomic)
    private int _isTainted;      // 0 = false, 1 = true (atomic)
    private int _isAutoDestroyed; // 0 = false, 1 = true (atomic)

    /// <summary>Unique identifier for this security context instance.</summary>
    public Guid InstanceId { get; }
    /// <summary>True if this instance has been marked as compromised (cross-thread visible).</summary>
    public bool IsCompromised => Volatile.Read(ref _isCompromised) == 1;
    /// <summary>True if this instance carries taint from a demotion or compromised operand (cross-thread visible).</summary>
    public bool IsTainted => Volatile.Read(ref _isTainted) == 1;
    /// <summary>Total number of decryption operations performed.</summary>
    public int DecryptionCount => Volatile.Read(ref _decryptionCount);
    /// <summary>Total number of operations performed.</summary>
    public int OperationCount => Volatile.Read(ref _operationCount);
    /// <summary>UTC timestamp when this context was created.</summary>
    public DateTime CreatedUtc { get; }
    /// <summary>True if the auto-destroy threshold was reached and disposal was triggered.</summary>
    public bool IsAutoDestroyed => Volatile.Read(ref _isAutoDestroyed) == 1;

    /// <summary>Raised when the auto-destroy threshold is reached and disposal is triggered.</summary>
    public event Action<SecurityContext>? AutoDestroyTriggered;

    /// <summary>Initializes a new <see cref="SecurityContext"/> with the specified instance ID, decryption limit, and optional rate limit.</summary>
    public SecurityContext(Guid instanceId, int maxDecryptionCount, int? decryptionRateLimit = null)
    {
        InstanceId = instanceId;
        _maxDecryptionCount = maxDecryptionCount;
        _decryptionRateLimit = decryptionRateLimit;
        CreatedUtc = DateTime.UtcNow;

        // Circular buffer for rate limiting timestamps
        _decryptionTimestamps = decryptionRateLimit.HasValue
            ? new long[decryptionRateLimit.Value]
            : [];
    }

    /// <summary>Marks this context as compromised. Thread-safe (atomic write).</summary>
    public void MarkCompromised()
    {
        Interlocked.Exchange(ref _isCompromised, 1);
    }

    /// <summary>Marks this context as tainted. Thread-safe (atomic write).</summary>
    public void MarkTainted()
    {
        Interlocked.Exchange(ref _isTainted, 1);
    }

    /// <summary>Raised when the taint flag is cleared, providing the reason string.</summary>
    public event Action<SecurityContext, string>? TaintCleared;

    /// <summary>Clears the taint flag with a mandatory reason. Thread-safe (atomic write).</summary>
    public void ClearTaint(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        Interlocked.Exchange(ref _isTainted, 0);
        TaintCleared?.Invoke(this, reason);
    }

    /// <summary>Records a decryption operation, enforcing rate limits and checking the auto-destroy threshold.</summary>
    public void IncrementDecryption()
    {
        CheckRateLimit();
        Interlocked.Increment(ref _decryptionCount);
        CheckAutoDestroy();
    }

    /// <summary>Increments the total operation count. Thread-safe (atomic increment).</summary>
    public void IncrementOperation()
    {
        Interlocked.Increment(ref _operationCount);
    }

    /// <summary>Checks if the decryption count has reached the auto-destroy threshold and triggers disposal if so.</summary>
    public void CheckAutoDestroy()
    {
        if (!IsAutoDestroyed && Volatile.Read(ref _decryptionCount) >= _maxDecryptionCount)
        {
            Interlocked.Exchange(ref _isAutoDestroyed, 1);
            AutoDestroyTriggered?.Invoke(this);
        }
    }

    private void CheckRateLimit()
    {
        if (!_decryptionRateLimit.HasValue)
            return;

        var limit = _decryptionRateLimit.Value;
        var now = DateTime.UtcNow.Ticks;
        var windowTicks = TimeSpan.TicksPerSecond; // 1-second window

        lock (_rateLimitLock)
        {
            // If buffer is full, check if the oldest entry in the window is within the last second
            if (_timestampCount >= limit)
            {
                var oldestInWindow = _decryptionTimestamps[_timestampIndex];
                if (now - oldestInWindow < windowTicks)
                {
                    throw new RateLimitExceededException(InstanceId, limit);
                }
            }

            // Record this timestamp
            _decryptionTimestamps[_timestampIndex] = now;
            _timestampIndex = (_timestampIndex + 1) % limit;
            if (_timestampCount < limit)
                _timestampCount++;
        }
    }
}
