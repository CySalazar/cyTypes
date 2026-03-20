using CyTypes.Collections;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Collections.Tests;

public sealed class CyListTests
{
    [Fact]
    public void Add_and_Count()
    {
        using var list = new CyList<CyInt>();
        list.Count.Should().Be(0);

        using var item = new CyInt(42);
        list.Add(item);
        list.Count.Should().Be(1);
    }

    [Fact]
    public void Add_null_throws_ArgumentNullException()
    {
        using var list = new CyList<CyInt>();
        var act = () => list.Add(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Indexer_returns_correct_item()
    {
        using var list = new CyList<CyInt>();
        using var a = new CyInt(10);
        using var b = new CyInt(20);
        list.Add(a);
        list.Add(b);

        list[0].Should().BeSameAs(a);
        list[1].Should().BeSameAs(b);
    }

    [Fact]
    public void Indexer_out_of_range_throws()
    {
        using var list = new CyList<CyInt>();
        var act = () => list[0];
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Remove_returns_true_for_existing_item()
    {
        using var list = new CyList<CyInt>();
        using var item = new CyInt(5);
        list.Add(item);

        list.Remove(item).Should().BeTrue();
        list.Count.Should().Be(0);
    }

    [Fact]
    public void Remove_returns_false_for_missing_item()
    {
        using var list = new CyList<CyInt>();
        using var item = new CyInt(5);

        list.Remove(item).Should().BeFalse();
    }

    [Fact]
    public void Contains_finds_existing_item()
    {
        using var list = new CyList<CyInt>();
        using var item = new CyInt(7);
        list.Add(item);

        list.Contains(item).Should().BeTrue();
    }

    [Fact]
    public void Contains_returns_false_for_missing_item()
    {
        using var list = new CyList<CyInt>();
        using var item = new CyInt(7);

        list.Contains(item).Should().BeFalse();
    }

    [Fact]
    public void Clear_disposes_all_items()
    {
        using var list = new CyList<CyInt>();
        var a = new CyInt(1);
        var b = new CyInt(2);
        list.Add(a);
        list.Add(b);

        list.Clear();

        list.Count.Should().Be(0);
        a.IsDisposed.Should().BeTrue();
        b.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void GetEnumerator_iterates_all_items()
    {
        using var list = new CyList<CyInt>();
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        using var c = new CyInt(3);
        list.Add(a);
        list.Add(b);
        list.Add(c);

        var items = new List<CyInt>();
        foreach (var item in list)
            items.Add(item);

        items.Should().HaveCount(3);
        items.Should().ContainInOrder(a, b, c);
    }

    [Fact]
    public void Linq_works_via_IEnumerable()
    {
        using var list = new CyList<CyInt>();
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        list.Add(a);
        list.Add(b);

        list.ToList().Should().HaveCount(2);
        list[0].Should().BeSameAs(a);
        list[list.Count - 1].Should().BeSameAs(b);
    }

    [Fact]
    public void Dispose_disposes_all_items()
    {
        var a = new CyInt(10);
        var b = new CyInt(20);
        var list = new CyList<CyInt>();
        list.Add(a);
        list.Add(b);

        list.Dispose();

        a.IsDisposed.Should().BeTrue();
        b.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Dispose_twice_does_not_throw()
    {
        var list = new CyList<CyInt>();
        var act = () =>
        {
            list.Dispose();
            list.Dispose();
        };
        act.Should().NotThrow();
    }

    [Fact]
    public void Add_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        using var item = new CyInt(1);
        var act = () => list.Add(item);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Remove_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        using var item = new CyInt(1);
        var act = () => list.Remove(item);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Indexer_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        var act = () => list[0];
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Contains_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        using var item = new CyInt(1);
        var act = () => list.Contains(item);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Count_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        var act = () => list.Count;
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Clear_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        var act = () => list.Clear();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void GetEnumerator_after_dispose_throws_ObjectDisposedException()
    {
        var list = new CyList<CyInt>();
        list.Dispose();

        var act = () => list.GetEnumerator();
        act.Should().Throw<ObjectDisposedException>();
    }
}
