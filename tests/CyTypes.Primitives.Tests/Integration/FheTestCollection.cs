using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

/// <summary>
/// xUnit collection that serializes tests touching the global FheEngineProvider.
/// Without this, parallel test classes can race on Configure/Reset of the static provider.
/// </summary>
[CollectionDefinition("FHE")]
public sealed class FheSerializedTests : ICollectionFixture<FheSerializedTests.NoOp>
{
    public sealed class NoOp { }
}
