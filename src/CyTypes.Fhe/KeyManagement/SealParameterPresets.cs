using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.KeyManagement;

/// <summary>
/// Predefined SEAL parameter sets for BFV and CKKS schemes.
/// </summary>
public static class SealParameterPresets
{
    private static readonly int[] Ckks128BitModuli = [60, 40, 40, 60];
    private static readonly int[] Ckks192BitModuli = [60, 40, 40, 40, 40, 40, 60];

    /// <summary>
    /// BFV parameters targeting 128-bit security: poly_modulus_degree=4096.
    /// </summary>
    public static EncryptionParameters Bfv128Bit()
    {
        var parms = new EncryptionParameters(SchemeType.BFV);
        parms.PolyModulusDegree = 4096;
        parms.CoeffModulus = CoeffModulus.BFVDefault(4096);
        parms.PlainModulus = PlainModulus.Batching(4096, 20);
        return parms;
    }

    /// <summary>
    /// BFV parameters targeting 192-bit security: poly_modulus_degree=8192.
    /// </summary>
    public static EncryptionParameters Bfv192Bit()
    {
        var parms = new EncryptionParameters(SchemeType.BFV);
        parms.PolyModulusDegree = 8192;
        parms.CoeffModulus = CoeffModulus.BFVDefault(8192);
        parms.PlainModulus = PlainModulus.Batching(8192, 20);
        return parms;
    }

    /// <summary>The default scale for CKKS encoding: 2^40.</summary>
    public static readonly double DefaultCkksScale = Math.Pow(2, 40);

    /// <summary>
    /// CKKS parameters targeting 128-bit security: poly_modulus_degree=8192.
    /// Coefficient modulus chain: {60, 40, 40, 60} — supports 2 multiplications before exhaustion.
    /// </summary>
    public static EncryptionParameters Ckks128Bit()
    {
        var parms = new EncryptionParameters(SchemeType.CKKS);
        parms.PolyModulusDegree = 8192;
        parms.CoeffModulus = CoeffModulus.Create(8192, Ckks128BitModuli);
        return parms;
    }

    /// <summary>
    /// CKKS parameters targeting 192-bit security: poly_modulus_degree=16384.
    /// Coefficient modulus chain: {60, 40, 40, 40, 40, 40, 60} — supports 5 multiplications.
    /// </summary>
    public static EncryptionParameters Ckks192Bit()
    {
        var parms = new EncryptionParameters(SchemeType.CKKS);
        parms.PolyModulusDegree = 16384;
        parms.CoeffModulus = CoeffModulus.Create(16384, Ckks192BitModuli);
        return parms;
    }
}
