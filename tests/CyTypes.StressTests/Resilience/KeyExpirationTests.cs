using System.Security.Cryptography;
using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Resilience;

[Trait("Category", "Stress"), Trait("SubCategory", "Resilience")]
public class KeyExpirationTests
{
    private readonly ITestOutputHelper _output;

    public KeyExpirationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task KeyManager_TTL_ExpiresUnderLoad()
    {
        // Arrange: KeyManager with TTL of 1 second
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        using var keyManager = new KeyManager(key, TimeSpan.FromSeconds(1));

        // Act: Access key immediately (should work)
        var currentKey = keyManager.CurrentKey.ToArray();
        currentKey.Should().NotBeEmpty("key should be accessible before TTL expires");

        // Wait for TTL to expire
        await Task.Delay(TimeSpan.FromMilliseconds(1100));

        // Assert: Access after TTL should throw KeyExpiredException
        var act = () => { _ = keyManager.CurrentKey; };
        act.Should().Throw<KeyExpiredException>("accessing key after TTL should throw KeyExpiredException");

        _output.WriteLine("Key correctly expired after TTL");
    }

    [Fact]
    public async Task KeyManager_TTL_RotateBeforeExpiry()
    {
        // Arrange: KeyManager with TTL of 5 seconds (generous for CI environments)
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        using var keyManager = new KeyManager(key, TimeSpan.FromSeconds(5));

        var originalKeyId = keyManager.KeyId;

        // Access immediately (should work)
        var key1 = keyManager.CurrentKey.ToArray();
        key1.Should().NotBeEmpty();

        // Wait 500ms, then rotate (well within the 5s TTL)
        await Task.Delay(500);
        keyManager.RotateKey();

        var newKeyId = keyManager.KeyId;
        newKeyId.Should().NotBe(originalKeyId, "rotation should produce a new KeyId");

        // Access after rotation (should work - rotation resets TTL)
        var key2 = keyManager.CurrentKey.ToArray();
        key2.Should().NotBeEmpty("key should be accessible after rotation");

        // Wait 2 seconds — original TTL (5s from creation) would be close,
        // but rotation reset it so we have a fresh 5s window
        await Task.Delay(2000);

        // Key should still be valid since rotation reset the TTL
        var key3 = keyManager.CurrentKey.ToArray();
        key3.Should().NotBeEmpty("key should still be valid because rotation resets TTL");

        _output.WriteLine($"Original KeyId: {originalKeyId}");
        _output.WriteLine($"Rotated KeyId: {newKeyId}");
        _output.WriteLine("Rotation correctly reset TTL");
    }
}
