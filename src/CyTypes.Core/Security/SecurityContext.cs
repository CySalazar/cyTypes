namespace CyTypes.Core.Security;

/// <summary>Immutable snapshot of combined security flags from a single atomic read.</summary>
public readonly record struct SecurityState(bool IsCompromised, bool IsTainted, bool IsAutoDestroyed)
{
    /// <summary>True if either compromised or tainted.</summary>
    public bool IsDegraded => IsCompromised || IsTainted;
}

/// <summary>Tracks security state for a CyType instance, including decryption counts, rate limiting, and compromise flags.</summary>
public sealed class SecurityContext
{
    private readonly int _maxDecryptionCount;
    private readonly int? _decryptionRateLimit;
    private readonly long _rateLimitWindowTicks;
    private int _decryptionCount;
    private int _operationCount;
    private readonly object _rateLimitLock = new();
    private readonly long[] _decryptionTimestamps;
    private int _timestampIndex;
    private int _timestampCount;

    // Combined security flags — single int for atomic reads/writes via Volatile/Interlocked.
    // Bit 0 (0x1): IsCompromised (monotonic 0→1)
    // Bit 1 (0x2): IsTainted (bidirectional via ClearTaint)
    // Bit 2 (0x4): IsAutoDestroyed (monotonic 0→1)
    private int _securityFlags;
    private const int FlagCompromised = 0x1;
    private const int FlagTainted = 0x2;
    private const int FlagAutoDestroyed = 0x4;

    /// <summary>Unique identifier for this security context instance.</summary>
    public Guid InstanceId { get; }
    /// <summary>True if this instance has been marked as compromised (cross-thread visible).</summary>
    public bool IsCompromised => (Volatile.Read(ref _securityFlags) & FlagCompromised) != 0;
    /// <summary>True if this instance carries taint from a demotion or compromised operand (cross-thread visible).</summary>
    public bool IsTainted => (Volatile.Read(ref _securityFlags) & FlagTainted) != 0;
    /// <summary>Total number of decryption operations performed.</summary>
    public int DecryptionCount => Volatile.Read(ref _decryptionCount);
    /// <summary>Total number of operations performed.</summary>
    public int OperationCount => Volatile.Read(ref _operationCount);
    /// <summary>UTC timestamp when this context was created.</summary>
    public DateTime CreatedUtc { get; }
    /// <summary>True if the auto-destroy threshold was reached and disposal was triggered.</summary>
    public bool IsAutoDestroyed => (Volatile.Read(ref _securityFlags) & FlagAutoDestroyed) != 0;

    /// <summary>Raised when the auto-destroy threshold is reached and disposal is triggered.</summary>
    public event Action<SecurityContext>? AutoDestroyTriggered;

    /// <summary>Initializes a new <see cref="SecurityContext"/> with the specified instance ID, decryption limit, and optional rate limit.</summary>
    /// <param name="instanceId">Unique identifier for this context.</param>
    /// <param name="maxDecryptionCount">Maximum decryptions before auto-destroy.</param>
    /// <param name="decryptionRateLimit">Maximum decryptions per window, or null for unlimited.</param>
    /// <param name="decryptionRateLimitWindow">Sliding window for rate limiting. Defaults to 1 second.</param>
    public SecurityContext(Guid instanceId, int maxDecryptionCount, int? decryptionRateLimit = null, TimeSpan? decryptionRateLimitWindow = null)
    {
        InstanceId = instanceId;
        _maxDecryptionCount = maxDecryptionCount;
        _decryptionRateLimit = decryptionRateLimit;
        _rateLimitWindowTicks = (decryptionRateLimitWindow ?? TimeSpan.FromSeconds(1)).Ticks;
        CreatedUtc = DateTime.UtcNow;

        // Circular buffer for rate limiting timestamps
        _decryptionTimestamps = decryptionRateLimit.HasValue
            ? new long[decryptionRateLimit.Value]
            : [];
    }

    /// <summary>
    /// Returns a consistent snapshot of all security flags from a single atomic read.
    /// Use instead of reading IsCompromised/IsTainted separately when both are needed.
    /// </summary>
    public SecurityState GetSecurityState()
    {
        var flags = Volatile.Read(ref _securityFlags);
        return new SecurityState(
            (flags & FlagCompromised) != 0,
            (flags & FlagTainted) != 0,
            (flags & FlagAutoDestroyed) != 0);
    }

    /// <summary>Marks this context as compromised. Thread-safe (atomic CAS).</summary>
    public void MarkCompromised()
    {
        SetFlag(FlagCompromised);
    }

    /// <summary>Marks this context as tainted. Thread-safe (atomic CAS).</summary>
    public void MarkTainted()
    {
        SetFlag(FlagTainted);
    }

    /// <summary>Raised when the taint flag is cleared, providing the reason string.</summary>
    public event Action<SecurityContext, string>? TaintCleared;

    /// <summary>Clears the taint flag with a mandatory reason. Thread-safe (atomic CAS).</summary>
    public void ClearTaint(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ClearFlag(FlagTainted);
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
        var flags = Volatile.Read(ref _securityFlags);
        if ((flags & FlagAutoDestroyed) == 0 && Volatile.Read(ref _decryptionCount) >= _maxDecryptionCount)
        {
            if (SetFlag(FlagAutoDestroyed))
                AutoDestroyTriggered?.Invoke(this);
        }
    }

    /// <summary>Atomically sets a flag bit. Returns true if the flag was newly set (was 0 before).</summary>
    private bool SetFlag(int flag)
    {
        int current, desired;
        do
        {
            current = Volatile.Read(ref _securityFlags);
            if ((current & flag) != 0) return false; // already set
            desired = current | flag;
        } while (Interlocked.CompareExchange(ref _securityFlags, desired, current) != current);
        return true;
    }

    /// <summary>Atomically clears a flag bit.</summary>
    private void ClearFlag(int flag)
    {
        int current, desired;
        do
        {
            current = Volatile.Read(ref _securityFlags);
            desired = current & ~flag;
        } while (Interlocked.CompareExchange(ref _securityFlags, desired, current) != current);
    }

    private void CheckRateLimit()
    {
        if (!_decryptionRateLimit.HasValue)
            return;

        var limit = _decryptionRateLimit.Value;
        var now = DateTime.UtcNow.Ticks;
        var windowTicks = _rateLimitWindowTicks;

        lock (_rateLimitLock)
        {
            // If buffer is full, check if the oldest entry in the window is within the rate limit window
            if (_timestampCount >= limit)
            {
                var oldestInWindow = _decryptionTimestamps[_timestampIndex];
                if (now - oldestInWindow < windowTicks)
                {
                    throw new RateLimitExceededException(InstanceId, limit, TimeSpan.FromTicks(windowTicks));
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
