using CyTypes.Core.Crypto.Interfaces;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CyTypes.Core.Crypto.Pqc;

/// <summary>
/// ML-KEM-1024 (NIST Level 5) key encapsulation mechanism using BouncyCastle.
/// Keys are serialized using SubjectPublicKeyInfo (public) and PrivateKeyInfo (secret) DER encoding.
/// </summary>
public sealed class MlKemKeyEncapsulation : IPqcKeyEncapsulation
{
    private static readonly MLKemParameters Parameters = MLKemParameters.ml_kem_1024;

    /// <inheritdoc/>
    public (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = new SecureRandom();
        var keyGenParams = new MLKemKeyGenerationParameters(random, Parameters);
        var keyGen = new MLKemKeyPairGenerator();
        keyGen.Init(keyGenParams);

        var keyPair = keyGen.GenerateKeyPair();
        var pubKey = (MLKemPublicKeyParameters)keyPair.Public;
        var privKey = (MLKemPrivateKeyParameters)keyPair.Private;

        var pubEncoded = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey).GetDerEncoded();
        var privEncoded = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey).GetDerEncoded();

        return (pubEncoded, privEncoded);
    }

    /// <inheritdoc/>
    public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        var pubKeyParams = (MLKemPublicKeyParameters)PublicKeyFactory.CreateKey(publicKey);
        var encapsulator = new MLKemEncapsulator(Parameters);
        encapsulator.Init(pubKeyParams);

        var encBuf = new byte[encapsulator.EncapsulationLength];
        var secBuf = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(encBuf, 0, encBuf.Length, secBuf, 0, secBuf.Length);

        return (encBuf, secBuf);
    }

    /// <inheritdoc/>
    public byte[] Decapsulate(byte[] ciphertext, byte[] secretKey)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(secretKey);

        var privKeyParams = (MLKemPrivateKeyParameters)PrivateKeyFactory.CreateKey(secretKey);
        var decapsulator = new MLKemDecapsulator(Parameters);
        decapsulator.Init(privKeyParams);

        var secBuf = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, secBuf, 0, secBuf.Length);

        return secBuf;
    }
}
