using CyTypes.Core.Crypto.Pqc;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class MlKemKeyPairTests
{
    [Fact]
    public void Constructor_throws_on_null_publicKey()
    {
        var act = () => new MlKemKeyPair(null!, new byte[] { 1 });
        act.Should().Throw<ArgumentNullException>().WithParameterName("publicKey");
    }

    [Fact]
    public void Constructor_throws_on_null_secretKey()
    {
        var act = () => new MlKemKeyPair(new byte[] { 1 }, null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("secretKey");
    }

    [Fact]
    public void Dispose_zeros_both_keys()
    {
        var pk = new byte[] { 1, 2, 3 };
        var sk = new byte[] { 4, 5, 6 };
        var kp = new MlKemKeyPair(pk, sk);

        kp.Dispose();

        kp.PublicKey.Should().AllBeEquivalentTo((byte)0);
        kp.SecretKey.Should().AllBeEquivalentTo((byte)0);
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var kp = new MlKemKeyPair(new byte[] { 1 }, new byte[] { 2 });

        kp.Dispose();
        kp.Dispose();

        kp.SecretKey.Should().AllBeEquivalentTo((byte)0);
    }
}
