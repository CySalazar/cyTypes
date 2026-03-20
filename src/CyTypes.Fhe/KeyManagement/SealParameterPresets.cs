using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.KeyManagement;

/// <summary>
/// Predefined SEAL parameter sets for BFV scheme.
/// </summary>
public static class SealParameterPresets
{
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
}
