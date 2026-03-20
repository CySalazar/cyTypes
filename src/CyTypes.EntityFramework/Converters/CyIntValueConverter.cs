using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyInt"/> to and from <see cref="int"/> for EF Core persistence.
/// </summary>
public sealed class CyIntValueConverter : ValueConverter<CyInt, int>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyIntValueConverter"/> class.
    /// </summary>
    public CyIntValueConverter()
        : base(
            cy => cy.ToInsecureInt(),
            value => Create(value))
    {
    }

    private static CyInt Create(int value) => new(value);
}
