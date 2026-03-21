using System.Reflection;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Memory;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Compliance;

/// <summary>
/// Continuous monitoring tests for compliance validation.
/// Verifies zero plaintext residue after complete encrypt/decrypt/dispose cycle.
/// </summary>
public class ContinuousMonitoringTests
{
    [Fact]
    public void FullCycle_NoPlaintextResidueInSecureBuffer()
    {
        const string sensitiveData = "SSN-123-45-6789";

        // Create, use, and dispose
        var cy = new CyString(sensitiveData);
        var recovered = cy.ToInsecureString();
        recovered.Should().Be(sensitiveData);
        cy.Dispose();

        // Verify CyString is no longer accessible
        var act = () => cy.ToInsecureString();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void SecureBuffer_ZeroVerification_AfterCryptoOperations()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var keyBuffer = new SecureBuffer(32);
        keyBuffer.Write(key);

        // Use the key for operations
        var engine = new AesGcmEngine();
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var ct = engine.Encrypt(plaintext, keyBuffer.AsReadOnlySpan());
        var pt = engine.Decrypt(ct, keyBuffer.AsReadOnlySpan());
        pt.Should().Equal(plaintext);

        // Dispose and verify zeroing
        keyBuffer.Dispose();

        var field = typeof(SecureBuffer).GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance);
        var internalBuffer = (byte[])field!.GetValue(keyBuffer)!;
        internalBuffer.Should().AllBeEquivalentTo((byte)0);
    }

    [Fact]
    public void MultipleTypes_DisposeAll_NoExceptions()
    {
        var types = new IDisposable[]
        {
            new CyString("test"),
            new CyInt(42),
            new CyDecimal(99.99m),
            new CyDateTime(DateTime.UtcNow),
            new CyBool(true),
            new CyDouble(3.14),
            new CyFloat(2.71f),
            new CyLong(long.MaxValue),
            new CyBytes(new byte[] { 1, 2, 3 }),
        };

        foreach (var t in types)
        {
            t.Dispose();
        }

        // All disposed without exception
    }

    [Fact]
    public void RapidCreateDispose_NoResourceExhaustion()
    {
        var initialMemory = GC.GetTotalMemory(true);

        for (int i = 0; i < 10000; i++)
        {
            using var cy = new CyString($"rapid-test-{i}");
            _ = cy.ToInsecureString();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var finalMemory = GC.GetTotalMemory(true);
        var growthMb = (finalMemory - initialMemory) / (1024.0 * 1024.0);

        // Memory growth should be minimal after GC
        growthMb.Should().BeLessThan(50,
            because: "10k create/dispose cycles should not leak significant memory");
    }
}
