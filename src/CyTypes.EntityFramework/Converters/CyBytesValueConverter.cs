using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyBytes"/> to and from byte[] for EF Core persistence.
/// </summary>
public sealed class CyBytesValueConverter : ValueConverter<CyBytes, byte[]>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyBytesValueConverter"/> class.
    /// </summary>
    public CyBytesValueConverter()
        : base(
            cy => cy.ToInsecureBytes(),
            value => Create(value))
    {
    }

    private static CyBytes Create(byte[] value) => new(value);
}
