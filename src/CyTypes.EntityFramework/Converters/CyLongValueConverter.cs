using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyLong"/> to and from <see cref="long"/> for EF Core persistence.
/// </summary>
public sealed class CyLongValueConverter : ValueConverter<CyLong, long>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyLongValueConverter"/> class.
    /// </summary>
    public CyLongValueConverter()
        : base(
            cy => cy.ToInsecureLong(),
            value => Create(value))
    {
    }

    private static CyLong Create(long value) => new(value);
}
