using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA.AsymmetricAlgorithm;

public abstract class EdDsaTestBase
{
    protected static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
    {
        var keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.GenerateKeyPair();
    }
    
    protected static AsymmetricCipherKeyPair GenerateEd448KeyPair()
    {
        var keyPairGenerator = new Ed448KeyPairGenerator();
        keyPairGenerator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.GenerateKeyPair();
    }
    
}