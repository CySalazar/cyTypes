using System.Collections.Concurrent;
using Xunit;
using FluentAssertions;
using CyTypes.Core.Security;
using CyTypes.Core.Policy.Components;
using Microsoft.Extensions.Logging.Abstractions;

namespace CyTypes.Core.Tests.Unit.Security;

public class SecurityAuditorTests
{
    private readonly SecurityAuditor _auditor = new(NullLogger<SecurityAuditor>.Instance);

    private static SecurityEvent MakeEvent(SecurityEventType eventType = SecurityEventType.Decrypted) =>
        new(DateTime.UtcNow, eventType, Guid.NewGuid(), "test", "TestPolicy");

    [Fact]
    public void RecordEvent_AtAllOperationsLevel_RecordsEvent()
    {
        var evt = MakeEvent(SecurityEventType.OperationPerformed);

        _auditor.RecordEvent(evt, AuditLevel.AllOperations);

        _auditor.GetRecentEvents().Should().ContainSingle().Which.Should().Be(evt);
    }

    [Theory]
    [InlineData(SecurityEventType.Decrypted, true)]
    [InlineData(SecurityEventType.Transferred, true)]
    [InlineData(SecurityEventType.Compromised, true)]
    [InlineData(SecurityEventType.AutoDestroyed, true)]
    [InlineData(SecurityEventType.KeyRotated, true)]
    [InlineData(SecurityEventType.OperationPerformed, false)]
    [InlineData(SecurityEventType.Created, false)]
    [InlineData(SecurityEventType.Encrypted, false)]
    [InlineData(SecurityEventType.Tainted, false)]
    [InlineData(SecurityEventType.PolicyChanged, false)]
    public void RecordEvent_AtDecryptionsAndTransfersLevel_FiltersCorrectly(
        SecurityEventType eventType, bool shouldBeRecorded)
    {
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance);
        var evt = MakeEvent(eventType);

        auditor.RecordEvent(evt, AuditLevel.DecryptionsAndTransfers);

        if (shouldBeRecorded)
            auditor.GetRecentEvents().Should().ContainSingle().Which.Should().Be(evt);
        else
            auditor.GetRecentEvents().Should().BeEmpty();
    }

    [Theory]
    [InlineData(SecurityEventType.Compromised, true)]
    [InlineData(SecurityEventType.AutoDestroyed, true)]
    [InlineData(SecurityEventType.Decrypted, false)]
    [InlineData(SecurityEventType.Transferred, false)]
    [InlineData(SecurityEventType.OperationPerformed, false)]
    public void RecordEvent_AtCompromiseOnlyLevel_FiltersCorrectly(
        SecurityEventType eventType, bool shouldBeRecorded)
    {
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance);
        var evt = MakeEvent(eventType);

        auditor.RecordEvent(evt, AuditLevel.CompromiseOnly);

        if (shouldBeRecorded)
            auditor.GetRecentEvents().Should().ContainSingle().Which.Should().Be(evt);
        else
            auditor.GetRecentEvents().Should().BeEmpty();
    }

    [Fact]
    public void RecordEvent_AtNoneLevel_RecordsNothing()
    {
        var evt = MakeEvent(SecurityEventType.Compromised);

        _auditor.RecordEvent(evt, AuditLevel.None);

        _auditor.GetRecentEvents().Should().BeEmpty();
    }

    [Fact]
    public void GetRecentEvents_ReturnsRecordedEvents()
    {
        var evt1 = MakeEvent(SecurityEventType.Decrypted);
        var evt2 = MakeEvent(SecurityEventType.Compromised);

        _auditor.RecordEvent(evt1, AuditLevel.AllOperations);
        _auditor.RecordEvent(evt2, AuditLevel.AllOperations);

        _auditor.GetRecentEvents().Should().HaveCount(2)
            .And.ContainInOrder(evt1, evt2);
    }

    [Fact]
    public void RingBuffer_KeepsMaximum1000Events()
    {
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance);

        for (int i = 0; i < 1005; i++)
            auditor.RecordEvent(MakeEvent(), AuditLevel.AllOperations);

        auditor.GetRecentEvents().Should().HaveCountLessOrEqualTo(1000);
    }

    // === IAuditSink Tests ===

    [Fact]
    public void Sink_receives_events_that_pass_audit_filter()
    {
        var sink = new CollectingSink();
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance, new[] { sink });

        var evt = MakeEvent(SecurityEventType.Compromised);
        auditor.RecordEvent(evt, AuditLevel.AllOperations);

        sink.Events.Should().ContainSingle().Which.Should().Be(evt);
    }

    [Fact]
    public void Sink_does_not_receive_filtered_events()
    {
        var sink = new CollectingSink();
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance, new[] { sink });

        var evt = MakeEvent(SecurityEventType.OperationPerformed);
        auditor.RecordEvent(evt, AuditLevel.CompromiseOnly);

        sink.Events.Should().BeEmpty();
    }

    [Fact]
    public void Multiple_sinks_all_receive_events()
    {
        var sink1 = new CollectingSink();
        var sink2 = new CollectingSink();
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance, new IAuditSink[] { sink1, sink2 });

        var evt = MakeEvent(SecurityEventType.Decrypted);
        auditor.RecordEvent(evt, AuditLevel.AllOperations);

        sink1.Events.Should().ContainSingle().Which.Should().Be(evt);
        sink2.Events.Should().ContainSingle().Which.Should().Be(evt);
    }

    [Fact]
    public void Failing_sink_does_not_prevent_other_sinks_from_receiving()
    {
        var failingSink = new FailingSink();
        var goodSink = new CollectingSink();
        var auditor = new SecurityAuditor(
            NullLogger<SecurityAuditor>.Instance,
            new IAuditSink[] { failingSink, goodSink });

        var evt = MakeEvent(SecurityEventType.Compromised);
        auditor.RecordEvent(evt, AuditLevel.AllOperations);

        // Good sink still receives the event despite failing sink
        goodSink.Events.Should().ContainSingle().Which.Should().Be(evt);

        // Ring buffer also has the event
        auditor.GetRecentEvents().Should().ContainSingle().Which.Should().Be(evt);
    }

    [Fact]
    public void Sink_receives_all_events_in_order()
    {
        var sink = new CollectingSink();
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance, new[] { sink });

        var events = Enumerable.Range(0, 10)
            .Select(_ => MakeEvent(SecurityEventType.Decrypted))
            .ToList();

        foreach (var evt in events)
            auditor.RecordEvent(evt, AuditLevel.AllOperations);

        sink.Events.Should().HaveCount(10).And.ContainInOrder(events);
    }

    [Fact]
    public void No_sinks_constructor_works_same_as_original()
    {
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance);
        var evt = MakeEvent(SecurityEventType.Decrypted);

        auditor.RecordEvent(evt, AuditLevel.AllOperations);

        auditor.GetRecentEvents().Should().ContainSingle().Which.Should().Be(evt);
    }

    [Fact]
    public void Sink_receives_events_beyond_ring_buffer_limit()
    {
        var sink = new CollectingSink();
        var auditor = new SecurityAuditor(NullLogger<SecurityAuditor>.Instance, new[] { sink });

        for (int i = 0; i < 1500; i++)
            auditor.RecordEvent(MakeEvent(), AuditLevel.AllOperations);

        // Ring buffer capped at 1000
        auditor.GetRecentEvents().Should().HaveCountLessOrEqualTo(1000);

        // Sink received all 1500 — no events lost
        sink.Events.Should().HaveCount(1500);
    }

    // === Test Helpers ===

    private sealed class CollectingSink : IAuditSink
    {
        private readonly ConcurrentBag<SecurityEvent> _events = new();
        public IReadOnlyList<SecurityEvent> Events => _events.ToArray().Reverse().ToArray();

        public void Receive(SecurityEvent securityEvent)
        {
            _events.Add(securityEvent);
        }
    }

    private sealed class FailingSink : IAuditSink
    {
        public void Receive(SecurityEvent securityEvent)
        {
            throw new InvalidOperationException("Simulated sink failure");
        }
    }
}
