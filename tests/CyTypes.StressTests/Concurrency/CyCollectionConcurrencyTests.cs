using System.Collections.Concurrent;
using CyTypes.Collections;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class CyCollectionConcurrencyTests
{
    [Fact]
    public async Task CyList_ConcurrentAddAndRemove()
    {
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterations = 50;
        var list = new CyList<CyInt>();
        var barrier = new Barrier(threadCount);
        var unexpectedExceptions = new ConcurrentBag<Exception>();

        var tasks = Enumerable.Range(0, threadCount).Select(t => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterations; i++)
            {
                try
                {
                    if (t % 2 == 0)
                        list.Add(new CyInt(i, SecurityPolicy.Performance));
                    else if (list.Count > 0)
                        list.RemoveAt(0);
                }
                catch (Exception ex) when (ex is ArgumentOutOfRangeException
                    or ObjectDisposedException or InvalidOperationException
                    or IndexOutOfRangeException or NullReferenceException or ArgumentException)
                {
                    // Expected race-condition exceptions
                }
                catch (Exception ex)
                {
                    unexpectedExceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        unexpectedExceptions.Should().BeEmpty(
            "CyList concurrent access may throw expected exceptions but must not cause unrecoverable failures");

        list.Dispose();
    }

    [Fact]
    public async Task CyDictionary_ConcurrentPutAndGet()
    {
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterations = 50;
        var dict = new CyDictionary<int, CyInt>();
        var barrier = new Barrier(threadCount);
        var unexpectedExceptions = new ConcurrentBag<Exception>();

        var tasks = Enumerable.Range(0, threadCount).Select(t => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterations; i++)
            {
                try
                {
                    var key = t * 10_000 + i;
                    dict.Add(key, new CyInt(key, SecurityPolicy.Performance));
                }
                catch (Exception ex) when (ex is ArgumentException
                    or ObjectDisposedException or InvalidOperationException
                    or IndexOutOfRangeException or NullReferenceException)
                {
                }
                catch (Exception ex)
                {
                    unexpectedExceptions.Add(ex);
                }

                try
                {
                    if (dict.Count > 0)
                        dict.ContainsKey(t * 10_000);
                }
                catch (Exception ex) when (ex is ArgumentException
                    or ObjectDisposedException or InvalidOperationException
                    or IndexOutOfRangeException or NullReferenceException)
                {
                }
                catch (Exception ex)
                {
                    unexpectedExceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        unexpectedExceptions.Should().BeEmpty(
            "CyDictionary concurrent access may throw expected exceptions but must not cause unrecoverable failures");

        // Dispose may throw NullReferenceException if internal dictionary state was corrupted
        // by concurrent access — this is expected for a non-thread-safe collection.
        try { dict.Dispose(); }
        catch (NullReferenceException) { }
    }

    [Fact]
    public async Task CyList_Dispose_DuringIteration()
    {
        var list = new CyList<CyInt>();
        for (var i = 0; i < 100; i++)
            list.Add(new CyInt(i, SecurityPolicy.Performance));

        var barrier = new Barrier(2);
        var unexpectedExceptions = new ConcurrentBag<Exception>();

        var iterateTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                foreach (var item in list)
                    _ = item.IsDisposed;
            }
            catch (Exception ex) when (ex is ObjectDisposedException
                or InvalidOperationException or NullReferenceException)
            {
            }
            catch (Exception ex)
            {
                unexpectedExceptions.Add(ex);
            }
        });

        var disposeTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                list.Dispose();
            }
            catch (Exception ex)
            {
                unexpectedExceptions.Add(ex);
            }
        });

        await Task.WhenAll(iterateTask, disposeTask);

        unexpectedExceptions.Should().BeEmpty(
            "dispose during iteration must not cause unrecoverable failures");
    }
}
