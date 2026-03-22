using System.Collections.Concurrent;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Resilience;

[Trait("Category", "Stress"), Trait("SubCategory", "Resilience")]
public class CorruptedCiphertextTests
{
    private readonly ITestOutputHelper _output;

    public CorruptedCiphertextTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task AesGcm_FlippedBit_ThrowsCryptographicException()
    {
        // Arrange
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "Hello, tamper test!"u8.ToArray();

        var ciphertext = engine.Encrypt(plaintext, key);

        // Flip a bit in the middle of the ciphertext
        var corrupted = (byte[])ciphertext.Clone();
        var midpoint = corrupted.Length / 2;
        corrupted[midpoint] ^= 0x01;

        // Act & Assert
        var act = () => engine.Decrypt(corrupted, key);
        act.Should().Throw<CryptographicException>("flipped bit should be detected by GCM tag verification");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task AesGcm_TruncatedCiphertext_Throws()
    {
        // Arrange
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "Truncation test data"u8.ToArray();

        var ciphertext = engine.Encrypt(plaintext, key);

        // Remove the last byte
        var truncated = new byte[ciphertext.Length - 1];
        Array.Copy(ciphertext, truncated, truncated.Length);

        // Act & Assert
        var act = () => engine.Decrypt(truncated, key);
        act.Should().Throw<Exception>("truncated ciphertext should fail decryption");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task AesGcm_WrongKey_Throws()
    {
        // Arrange
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var wrongKey = new byte[32];
        RandomNumberGenerator.Fill(wrongKey);
        var plaintext = "Wrong key test"u8.ToArray();

        var ciphertext = engine.Encrypt(plaintext, key);

        // Act & Assert
        var act = () => engine.Decrypt(ciphertext, wrongKey);
        act.Should().Throw<CryptographicException>("wrong key should fail GCM authentication");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task CorruptedCiphertext_UnderLoad()
    {
        // Arrange
        var threadCount = StressTestConfig.ConcurrentThreads;
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "Load test corruption"u8.ToArray();

        var ciphertext = engine.Encrypt(plaintext, key);
        var corrupted = (byte[])ciphertext.Clone();
        corrupted[corrupted.Length / 2] ^= 0xFF;

        var exceptions = new ConcurrentBag<Exception>();
        var cryptoExceptionCount = 0;
        var barrier = new Barrier(threadCount);

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                engine.Decrypt(corrupted, key);
                // Should not reach here
                exceptions.Add(new InvalidOperationException("Decrypt should have thrown"));
            }
            catch (CryptographicException)
            {
                Interlocked.Increment(ref cryptoExceptionCount);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("all threads should throw CryptographicException, not other exceptions");
        cryptoExceptionCount.Should().Be(threadCount, "every thread must detect the corruption");

        _output.WriteLine($"All {threadCount} threads correctly threw CryptographicException");
    }
}
