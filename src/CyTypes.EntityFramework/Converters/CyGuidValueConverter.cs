using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace CyTypes.EntityFramework.Converters;

/// <summary>
/// Converts <see cref="CyGuid"/> to and from <see cref="Guid"/> for EF Core persistence.
/// </summary>
public sealed class CyGuidValueConverter : ValueConverter<CyGuid, Guid>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CyGuidValueConverter"/> class.
    /// </summary>
    public CyGuidValueConverter()
        : base(
            cy => cy.ToInsecureGuid(),
            value => Create(value))
    {
    }

    private static CyGuid Create(Guid value) => new(value);
}
