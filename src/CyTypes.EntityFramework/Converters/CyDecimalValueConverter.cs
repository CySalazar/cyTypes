using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyDecimal"/> to and from <see cref="decimal"/> for EF Core persistence.
/// </summary>
public sealed class CyDecimalValueConverter : ValueConverter<CyDecimal, decimal>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyDecimalValueConverter"/> class.
    /// </summary>
    public CyDecimalValueConverter()
        : base(
            cy => cy.ToInsecureDecimal(),
            value => Create(value))
    {
    }

    private static CyDecimal Create(decimal value) => new(value);
}
