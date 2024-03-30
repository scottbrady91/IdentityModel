using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens;

/// <summary>
/// A Microsoft.IdentityModel security key for EdDSA.
/// </summary>
public class EdDsaSecurityKey : AsymmetricSecurityKey
{
    public EdDsa EdDsa { get; }
        
    private EdDsaSecurityKey()
    {
        CryptoProviderFactory.CustomCryptoProvider = new ExtendedCryptoProvider();
    }

    public EdDsaSecurityKey(EdDsa edDsaCreation) : this()
    {
        EdDsa = edDsaCreation ?? throw new ArgumentNullException(nameof(edDsaCreation));
    }
        
    [Obsolete("Deprecated in favor of EdDsa constructor")]
    public EdDsaSecurityKey(Ed25519PrivateKeyParameters keyParameters) : this()
    {
        if (keyParameters == null) throw new ArgumentNullException(nameof(keyParameters));
        EdDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = keyParameters.GetEncoded()});
    }

    [Obsolete("Deprecated in favor of EdDsa constructor")]
    public EdDsaSecurityKey(Ed25519PublicKeyParameters keyParameters) : this()
    {
        if (keyParameters == null) throw new ArgumentNullException(nameof(keyParameters));
        EdDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {X = keyParameters.GetEncoded()});
    }
    
    public override int KeySize => EdDsa.KeySize;

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
    public override bool HasPrivateKey => EdDsa.Parameters.D != null;

    public override PrivateKeyStatus PrivateKeyStatus
        => EdDsa.Parameters.D != null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
}