using System.Collections.Concurrent;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class AesGcmEngineConcurrencyTests
{
    [Fact]
    public async Task ConcurrentEncryptDecrypt_SameKey_AllRoundTrip()
    {
        // Arrange: N threads encrypt unique plaintexts with the same key, then decrypt
        var threadCount = StressTestConfig.ConcurrentThreads;
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var aad = "stress-test-aad"u8.ToArray();
        var barrier = new Barrier(threadCount);
        var results = new ConcurrentBag<(int ThreadId, bool Success)>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(threadId => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                // Each thread has a unique plaintext
                var plaintext = BitConverter.GetBytes(threadId);
                var ciphertext = engine.Encrypt(plaintext, key, aad);
                var decrypted = engine.Decrypt(ciphertext, key, aad);

                var roundTripped = BitConverter.ToInt32(decrypted);
                results.Add((threadId, roundTripped == threadId));
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("AES-GCM engine must be safe for concurrent use");
        results.Should().HaveCount(threadCount);
        results.Should().AllSatisfy(r => r.Success.Should().BeTrue(
            $"thread {r.ThreadId} round-trip must produce original plaintext"));
    }

    [Fact]
    public async Task HighFrequency_SmallPayloads_NoExhaustion()
    {
        // Arrange: tight loop of 1-byte encrypt/decrypt to detect resource exhaustion
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterations = StressTestConfig.IterationsPerThread;
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var barrier = new Barrier(threadCount);
        var totalOps = 0;
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterations; i++)
            {
                try
                {
                    var plaintext = new byte[] { (byte)(i % 256) };
                    var ciphertext = engine.Encrypt(plaintext, key);
                    var decrypted = engine.Decrypt(ciphertext, key);
                    decrypted.Should().BeEquivalentTo(plaintext);
                    Interlocked.Increment(ref totalOps);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("small-payload tight loop must not exhaust crypto resources");
        totalOps.Should().Be(threadCount * iterations);
    }
}
