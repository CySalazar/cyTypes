using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.KeyManagement;

public sealed class PlatformKeyStoreTests
{
    [Fact]
    public void InMemoryKeyStore_Store_and_retrieve_returns_same_data()
    {
        var store = new InMemoryKeyStore();
        var data = new byte[] { 1, 2, 3, 4, 5 };

        store.TryStore("test-key", data);
        var retrieved = store.TryRetrieve("test-key");

        retrieved.Should().NotBeNull();
        retrieved.Should().Equal(data);
    }

    [Fact]
    public void InMemoryKeyStore_Retrieve_non_existent_returns_null()
    {
        var store = new InMemoryKeyStore();

        var retrieved = store.TryRetrieve("does-not-exist");

        retrieved.Should().BeNull();
    }

    [Fact]
    public void InMemoryKeyStore_Delete_returns_true_for_existing()
    {
        var store = new InMemoryKeyStore();
        store.TryStore("key-to-delete", new byte[] { 10, 20 });

        var result = store.TryDelete("key-to-delete");

        result.Should().BeTrue();
    }

    [Fact]
    public void InMemoryKeyStore_Delete_returns_false_for_non_existent()
    {
        var store = new InMemoryKeyStore();

        var result = store.TryDelete("no-such-key");

        result.Should().BeFalse();
    }

    [Fact]
    public void PlatformKeyStoreFactory_Create_returns_non_null()
    {
        var store = PlatformKeyStoreFactory.Create();

        store.Should().NotBeNull();
    }
}
