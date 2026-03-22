using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class AutoDestroyBoundaryTests
{
    private readonly ITestOutputHelper _output;

    public AutoDestroyBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void AutoDestroy_ExactlyAtThreshold()
    {
        // SecurityPolicy.Maximum: MaxDecryptionCount=10, AutoDestroy=true
        var cyInt = new CyInt(42, SecurityPolicy.Maximum);

        // Decrypt exactly 10 times
        for (var i = 0; i < 10; i++)
        {
            try
            {
                var value = cyInt.ToInsecureInt();
                value.Should().Be(42);
                _output.WriteLine($"Decryption {i + 1}: OK (value={value})");
            }
            catch (ObjectDisposedException)
            {
                // AutoDestroy may trigger disposal before we finish the loop
                _output.WriteLine($"Decryption {i + 1}: ObjectDisposedException (auto-destroyed)");
                break;
            }
        }

        // After 10 decryptions, the instance should be disposed
        cyInt.IsDisposed.Should().BeTrue(
            "CyInt with Maximum policy should be auto-destroyed after reaching MaxDecryptionCount=10");
        _output.WriteLine("Instance is disposed after 10 decryptions as expected");
    }

    [Fact]
    public void AutoDestroy_OneBeforeThreshold()
    {
        // SecurityPolicy.Maximum: MaxDecryptionCount=10, AutoDestroy=true
        var cyInt = new CyInt(99, SecurityPolicy.Maximum);

        // Decrypt 9 times — one before threshold
        for (var i = 0; i < 9; i++)
        {
            var value = cyInt.ToInsecureInt();
            value.Should().Be(99);
        }

        // Should NOT be disposed yet
        cyInt.IsDisposed.Should().BeFalse(
            "CyInt should not be auto-destroyed before reaching the threshold of 10");
        _output.WriteLine("Instance is NOT disposed after 9 decryptions as expected");

        cyInt.Dispose(); // Clean up
    }

    [Fact]
    public async Task AutoDestroy_RapidDecrypts_NearThreshold()
    {
        // SecurityPolicy.Maximum: MaxDecryptionCount=10, AutoDestroy=true, RateLimit=10
        var cyInt = new CyInt(77, SecurityPolicy.Maximum);
        var successes = 0;
        var disposedExceptions = 0;
        var rateLimitExceptions = 0;
        var otherExceptions = 0;
        var lockObj = new object();

        // 50 threads all trying to decrypt concurrently
        var tasks = Enumerable.Range(0, 50).Select(_ => Task.Run(() =>
        {
            try
            {
                var value = cyInt.ToInsecureInt();
                value.Should().Be(77);
                lock (lockObj) successes++;
            }
            catch (ObjectDisposedException)
            {
                lock (lockObj) disposedExceptions++;
            }
            catch (Exception ex) when (ex.GetType().Name == "RateLimitExceededException")
            {
                lock (lockObj) rateLimitExceptions++;
            }
            catch
            {
                lock (lockObj) otherExceptions++;
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        _output.WriteLine($"Successes: {successes}");
        _output.WriteLine($"ObjectDisposedExceptions: {disposedExceptions}");
        _output.WriteLine($"RateLimitExceptions: {rateLimitExceptions}");
        _output.WriteLine($"Other exceptions: {otherExceptions}");

        // Total successful decryptions should not exceed MaxDecryptionCount
        successes.Should().BeLessThanOrEqualTo(10,
            "at most MaxDecryptionCount=10 decryptions should succeed before auto-destroy");
        otherExceptions.Should().Be(0, "no unexpected exceptions should occur");
    }
}
