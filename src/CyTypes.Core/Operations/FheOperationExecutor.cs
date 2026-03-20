using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Core.Operations;

/// <summary>
/// Thin forwarder for FHE operations. Delegates to <see cref="IFheEngine"/> if available,
/// otherwise throws <see cref="InvalidOperationException"/>.
/// </summary>
public sealed class FheOperationExecutor
{
    private readonly IFheEngine? _engine;

    /// <summary>Initializes a new executor, optionally backed by an FHE engine.</summary>
    public FheOperationExecutor(IFheEngine? engine = null)
    {
        _engine = engine;
    }

    /// <summary>Adds two FHE-encrypted ciphertexts.</summary>
    public byte[] Add(byte[] a, byte[] b) => GetEngine().Add(a, b);

    /// <summary>Subtracts two FHE-encrypted ciphertexts.</summary>
    public byte[] Subtract(byte[] a, byte[] b) => GetEngine().Subtract(a, b);

    /// <summary>Multiplies two FHE-encrypted ciphertexts.</summary>
    public byte[] Multiply(byte[] a, byte[] b) => GetEngine().Multiply(a, b);

    /// <summary>Negates an FHE-encrypted ciphertext.</summary>
    public byte[] Negate(byte[] a) => GetEngine().Negate(a);

    private IFheEngine GetEngine() =>
        _engine ?? throw new InvalidOperationException(
            "FHE engine not configured. Register via AddCyTypesFhe().");
}
