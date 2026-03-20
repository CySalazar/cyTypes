using System.Security.Cryptography;
using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.KeyManagement;

public sealed class KeyManagerTests
{
    [Fact]
    public void New_KeyManager_has_non_empty_CurrentKey_of_32_bytes()
    {
        using var km = new KeyManager();

        km.CurrentKey.Length.Should().Be(32);
        km.CurrentKey.ToArray().Should().NotBeEquivalentTo(new byte[32],
            "key should not be all zeros");
    }

    [Fact]
    public void New_KeyManager_has_non_empty_KeyId()
    {
        using var km = new KeyManager();

        km.KeyId.Should().NotBe(Guid.Empty);
    }

    [Fact]
    public void UsageCount_starts_at_zero()
    {
        using var km = new KeyManager();

        km.UsageCount.Should().Be(0);
    }

    [Fact]
    public void IncrementUsage_increases_UsageCount()
    {
        using var km = new KeyManager();

        km.IncrementUsage();
        km.IncrementUsage();
        km.IncrementUsage();

        km.UsageCount.Should().Be(3);
    }

    [Fact]
    public void RotateKey_changes_the_key_bytes()
    {
        using var km = new KeyManager();
        var originalKey = km.CurrentKey.ToArray();

        km.RotateKey();

        km.CurrentKey.ToArray().Should().NotEqual(originalKey);
    }

    [Fact]
    public void RotateKey_changes_the_KeyId()
    {
        using var km = new KeyManager();
        var originalId = km.KeyId;

        km.RotateKey();

        km.KeyId.Should().NotBe(originalId);
    }

    [Fact]
    public void RotateKey_resets_UsageCount_to_zero()
    {
        using var km = new KeyManager();
        km.IncrementUsage();
        km.IncrementUsage();
        km.UsageCount.Should().Be(2);

        km.RotateKey();

        km.UsageCount.Should().Be(0);
    }

    [Fact]
    public void Dispose_prevents_further_access_to_CurrentKey()
    {
        var km = new KeyManager();
        km.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { _ = km.CurrentKey.ToArray(); });
    }

    [Fact]
    public void Constructor_with_explicit_key_uses_that_key()
    {
        var explicitKey = new byte[32];
        RandomNumberGenerator.Fill(explicitKey);

        using var km = new KeyManager(explicitKey);

        km.CurrentKey.ToArray().Should().Equal(explicitKey);
    }

    [Fact]
    public void Constructor_with_wrong_key_length_throws_ArgumentException()
    {
        var shortKey = new byte[16];

        var act = () => new KeyManager(shortKey);

        act.Should().Throw<ArgumentException>()
            .And.ParamName.Should().Be("initialKey");
    }
}
