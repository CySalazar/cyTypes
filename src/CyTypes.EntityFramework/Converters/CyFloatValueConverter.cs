using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyFloat"/> to and from <see cref="float"/> for EF Core persistence.
/// </summary>
public sealed class CyFloatValueConverter : ValueConverter<CyFloat, float>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyFloatValueConverter"/> class.
    /// </summary>
    public CyFloatValueConverter()
        : base(
            cy => cy.ToInsecureFloat(),
            value => Create(value))
    {
    }

    private static CyFloat Create(float value) => new(value);
}
