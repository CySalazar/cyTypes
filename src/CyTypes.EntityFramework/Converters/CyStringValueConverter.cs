using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyString"/> to and from <see cref="string"/> for EF Core persistence.
/// </summary>
public sealed class CyStringValueConverter : ValueConverter<CyString, string>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyStringValueConverter"/> class.
    /// </summary>
    public CyStringValueConverter()
        : base(
            cy => cy.ToInsecureString(),
            value => Create(value))
    {
    }

    private static CyString Create(string value) => new(value);
}
