using CyTypes.Collections;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Collections.Tests;

public sealed class CyDictionaryTests
{
    [Fact]
    public void Add_and_Count()
    {
        using var dict = new CyDictionary<string, CyInt>();
        dict.Count.Should().Be(0);

        using var value = new CyInt(42);
        dict.Add("key", value);
        dict.Count.Should().Be(1);
    }

    [Fact]
    public void Add_null_key_throws()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var value = new CyInt(1);
        var act = () => dict.Add(null!, value);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Add_null_value_throws()
    {
        using var dict = new CyDictionary<string, CyInt>();
        var act = () => dict.Add("key", null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Add_duplicate_key_throws()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        dict.Add("key", a);

        var act = () => dict.Add("key", b);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Indexer_get_returns_correct_value()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var value = new CyInt(99);
        dict.Add("x", value);

        dict["x"].Should().BeSameAs(value);
    }

    [Fact]
    public void Indexer_get_missing_key_throws()
    {
        using var dict = new CyDictionary<string, CyInt>();
        var act = () => dict["missing"];
        act.Should().Throw<KeyNotFoundException>();
    }

    [Fact]
    public void Indexer_set_replaces_and_disposes_old_value()
    {
        using var dict = new CyDictionary<string, CyInt>();
        var old = new CyInt(1);
        using var replacement = new CyInt(2);
        dict.Add("key", old);

        dict["key"] = replacement;

        old.IsDisposed.Should().BeTrue();
        dict["key"].Should().BeSameAs(replacement);
    }

    [Fact]
    public void Indexer_set_null_value_throws()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var value = new CyInt(1);
        dict.Add("key", value);

        var act = () => dict["key"] = null!;
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Remove_existing_key_returns_true_and_disposes_value()
    {
        using var dict = new CyDictionary<string, CyInt>();
        var value = new CyInt(42);
        dict.Add("key", value);

        dict.Remove("key").Should().BeTrue();
        dict.Count.Should().Be(0);
        value.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Remove_missing_key_returns_false()
    {
        using var dict = new CyDictionary<string, CyInt>();
        dict.Remove("nope").Should().BeFalse();
    }

    [Fact]
    public void ContainsKey_returns_true_for_existing()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var value = new CyInt(1);
        dict.Add("key", value);

        dict.ContainsKey("key").Should().BeTrue();
    }

    [Fact]
    public void ContainsKey_returns_false_for_missing()
    {
        using var dict = new CyDictionary<string, CyInt>();
        dict.ContainsKey("nope").Should().BeFalse();
    }

    [Fact]
    public void TryGetValue_returns_true_and_value_for_existing()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var value = new CyInt(77);
        dict.Add("key", value);

        dict.TryGetValue("key", out var result).Should().BeTrue();
        result.Should().BeSameAs(value);
    }

    [Fact]
    public void TryGetValue_returns_false_for_missing()
    {
        using var dict = new CyDictionary<string, CyInt>();
        dict.TryGetValue("nope", out var result).Should().BeFalse();
        result.Should().BeNull();
    }

    [Fact]
    public void Keys_returns_all_keys()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        dict.Add("alpha", a);
        dict.Add("beta", b);

        dict.Keys.Should().BeEquivalentTo(["alpha", "beta"]);
    }

    [Fact]
    public void Values_returns_all_values()
    {
        using var dict = new CyDictionary<string, CyInt>();
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        dict.Add("a", a);
        dict.Add("b", b);

        dict.Values.Should().BeEquivalentTo([a, b]);
    }

    [Fact]
    public void Clear_disposes_all_values()
    {
        using var dict = new CyDictionary<string, CyInt>();
        var a = new CyInt(1);
        var b = new CyInt(2);
        dict.Add("a", a);
        dict.Add("b", b);

        dict.Clear();

        dict.Count.Should().Be(0);
        a.IsDisposed.Should().BeTrue();
        b.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Dispose_disposes_all_values()
    {
        var a = new CyInt(10);
        var b = new CyInt(20);
        var dict = new CyDictionary<string, CyInt>();
        dict.Add("a", a);
        dict.Add("b", b);

        dict.Dispose();

        a.IsDisposed.Should().BeTrue();
        b.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Dispose_twice_does_not_throw()
    {
        var dict = new CyDictionary<string, CyInt>();
        var act = () =>
        {
            dict.Dispose();
            dict.Dispose();
        };
        act.Should().NotThrow();
    }

    [Fact]
    public void Add_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        using var value = new CyInt(1);
        var act = () => dict.Add("key", value);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Indexer_get_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        var act = () => dict["key"];
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Indexer_set_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        using var value = new CyInt(1);
        var act = () => dict["key"] = value;
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Remove_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        var act = () => dict.Remove("key");
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void ContainsKey_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        var act = () => dict.ContainsKey("key");
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void TryGetValue_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        var act = () => dict.TryGetValue("key", out _);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Clear_after_dispose_throws_ObjectDisposedException()
    {
        var dict = new CyDictionary<string, CyInt>();
        dict.Dispose();

        var act = () => dict.Clear();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Integer_keys_work()
    {
        using var dict = new CyDictionary<int, CyInt>();
        using var value = new CyInt(99);
        dict.Add(1, value);

        dict[1].Should().BeSameAs(value);
        dict.ContainsKey(1).Should().BeTrue();
        dict.ContainsKey(2).Should().BeFalse();
    }
}
