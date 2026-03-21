using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Security;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit;

public sealed class ExceptionTests
{
    [Fact]
    public void KeyExpiredException_stores_properties()
    {
        var keyId = Guid.NewGuid();
        var age = TimeSpan.FromHours(5);
        var ttl = TimeSpan.FromHours(1);

        var ex = new KeyExpiredException(keyId, age, ttl);

        ex.KeyId.Should().Be(keyId);
        ex.Age.Should().Be(age);
        ex.Ttl.Should().Be(ttl);
        ex.Message.Should().Contain("expired");
    }

    [Fact]
    public void PolicyViolationException_message_constructor()
    {
        var ex = new PolicyViolationException("test violation");

        ex.Message.Should().Be("test violation");
        ex.InnerException.Should().BeNull();
    }

    [Fact]
    public void PolicyViolationException_message_and_inner_constructor()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new PolicyViolationException("outer", inner);

        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void RateLimitExceededException_stores_properties()
    {
        var instanceId = Guid.NewGuid();
        const int limit = 100;

        var ex = new RateLimitExceededException(instanceId, limit);

        ex.InstanceId.Should().Be(instanceId);
        ex.Limit.Should().Be(limit);
        ex.Message.Should().Contain(instanceId.ToString());
        ex.Message.Should().Contain("100");
    }

    [Fact]
    public void SecurityEvent_record_stores_all_fields()
    {
        var timestamp = DateTime.UtcNow;
        var instanceId = Guid.NewGuid();

        var evt = new SecurityEvent(timestamp, SecurityEventType.Decrypted, instanceId, "test", "Default");

        evt.Timestamp.Should().Be(timestamp);
        evt.EventType.Should().Be(SecurityEventType.Decrypted);
        evt.InstanceId.Should().Be(instanceId);
        evt.Description.Should().Be("test");
        evt.PolicyName.Should().Be("Default");
    }

    [Fact]
    public void SecurityEvent_equality()
    {
        var timestamp = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var id = Guid.NewGuid();

        var a = new SecurityEvent(timestamp, SecurityEventType.Created, id, "d", "p");
        var b = new SecurityEvent(timestamp, SecurityEventType.Created, id, "d", "p");

        a.Should().Be(b);
    }
}
