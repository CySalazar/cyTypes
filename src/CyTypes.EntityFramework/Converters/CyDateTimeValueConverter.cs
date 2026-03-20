using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyDateTime"/> to and from <see cref="DateTime"/> for EF Core persistence.
/// </summary>
public sealed class CyDateTimeValueConverter : ValueConverter<CyDateTime, DateTime>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyDateTimeValueConverter"/> class.
    /// </summary>
    public CyDateTimeValueConverter()
        : base(
            cy => cy.ToInsecureDateTime(),
            value => Create(value))
    {
    }

    private static CyDateTime Create(DateTime value) => new(value);
}
