using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyBool"/> to and from <see cref="bool"/> for EF Core persistence.
/// </summary>
public sealed class CyBoolValueConverter : ValueConverter<CyBool, bool>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyBoolValueConverter"/> class.
    /// </summary>
    public CyBoolValueConverter()
        : base(
            cy => cy.ToInsecureBool(),
            value => Create(value))
    {
    }

    private static CyBool Create(bool value) => new(value);
}
