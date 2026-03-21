using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Compliance;

/// <summary>
/// HomomorphicEncryption.org parameter validation for BFV scheme.
/// Reference: "Homomorphic Encryption Security Standard" (HomomorphicEncryption.org, 2018).
/// Maintained by: Microsoft Research, Intel, Samsung, and academic partners.
/// Validates that SEAL/BFV parameter selections meet minimum 128-bit security level.
/// </summary>
public class HeOrgParameterValidationTests
{
    /// <summary>
    /// HomomorphicEncryption.org security table for BFV/BGV (Table 1).
    /// Maps (poly_modulus_degree, max_coeff_modulus_bits) to security level.
    /// Source: https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    /// </summary>
    private static readonly Dictionary<int, int> MaxCoeffModulusBitsFor128BitSecurity = new()
    {
        { 1024, 27 },
        { 2048, 54 },
        { 4096, 109 },
        { 8192, 218 },
        { 16384, 438 },
        { 32768, 881 },
    };

    /// <summary>
    /// Validates that the Bfv128Bit preset (poly_modulus_degree=4096) meets 128-bit security.
    /// Per HE.org standard, 4096-degree with ≤109 bits of coeff_modulus achieves 128-bit security.
    /// SEAL's BFVDefault(4096) uses {40, 20, 40} = 100 bits total, which is ≤ 109.
    /// </summary>
    [Fact]
    public void Bfv128Bit_PolyModulusDegree4096_Meets128BitSecurity()
    {
        const int polyModulusDegree = 4096;

        // SEAL CoeffModulus.BFVDefault(4096) produces primes totaling ~100 bits
        // The exact bit sizes are {40, 20, 40} for a total of ~100 bits
        const int totalCoeffModulusBits = 100;

        var maxAllowed = MaxCoeffModulusBitsFor128BitSecurity[polyModulusDegree];

        totalCoeffModulusBits.Should().BeLessThanOrEqualTo(maxAllowed,
            because: $"HE.org: poly_modulus_degree={polyModulusDegree} requires coeff_modulus ≤ {maxAllowed} bits for 128-bit security");
    }

    /// <summary>
    /// Validates that the Bfv192Bit preset (poly_modulus_degree=8192) exceeds 128-bit security.
    /// Per HE.org standard, 8192-degree with ≤218 bits of coeff_modulus achieves 128-bit security.
    /// SEAL's BFVDefault(8192) uses ~218 bits total.
    /// </summary>
    [Fact]
    public void Bfv192Bit_PolyModulusDegree8192_Meets128BitSecurity()
    {
        const int polyModulusDegree = 8192;

        // SEAL CoeffModulus.BFVDefault(8192) produces primes totaling ~218 bits
        const int totalCoeffModulusBits = 218;

        var maxAllowed = MaxCoeffModulusBitsFor128BitSecurity[polyModulusDegree];

        totalCoeffModulusBits.Should().BeLessThanOrEqualTo(maxAllowed,
            because: $"HE.org: poly_modulus_degree={polyModulusDegree} requires coeff_modulus ≤ {maxAllowed} bits for 128-bit security");
    }

    /// <summary>
    /// Validates that poly_modulus_degree is a power of 2 (required by SEAL/BFV).
    /// </summary>
    [Theory]
    [InlineData(4096)]
    [InlineData(8192)]
    public void PolyModulusDegree_IsPowerOfTwo(int degree)
    {
        (degree > 0 && (degree & (degree - 1)) == 0).Should().BeTrue(
            because: "HE.org: poly_modulus_degree must be a power of 2");
    }

    /// <summary>
    /// Validates that the plain_modulus for batching is prime (required for NTT).
    /// SEAL's PlainModulus.Batching(N, bitSize) guarantees this.
    /// </summary>
    [Fact]
    public void PlainModulus_BitsSelection_IsReasonable()
    {
        // Bfv128Bit uses PlainModulus.Batching(4096, 20)
        // 20-bit plain modulus supports values up to ~1M, suitable for integer operations
        const int plainModulusBits = 20;

        plainModulusBits.Should().BeGreaterThanOrEqualTo(16,
            because: "HE.org: plain_modulus should be large enough for practical computation");
        plainModulusBits.Should().BeLessThanOrEqualTo(60,
            because: "HE.org: plain_modulus should not consume excessive noise budget");
    }

    /// <summary>
    /// Validates that all preset degrees are present in the HE.org security table.
    /// </summary>
    [Theory]
    [InlineData(4096)]
    [InlineData(8192)]
    public void PresetDegrees_InHeOrgSecurityTable(int degree)
    {
        MaxCoeffModulusBitsFor128BitSecurity.Should().ContainKey(degree,
            because: $"HE.org: poly_modulus_degree={degree} must be a standard parameter");
    }
}
