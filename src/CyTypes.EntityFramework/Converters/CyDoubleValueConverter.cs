using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyDouble"/> to and from <see cref="double"/> for EF Core persistence.
/// </summary>
public sealed class CyDoubleValueConverter : ValueConverter<CyDouble, double>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyDoubleValueConverter"/> class.
    /// </summary>
    public CyDoubleValueConverter()
        : base(
            cy => cy.ToInsecureDouble(),
            value => Create(value))
    {
    }

    private static CyDouble Create(double value) => new(value);
}
