using System;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens;

/// <summary>
/// A Microsoft.IdentityModel security key for EdDSA.
/// </summary>
public class EdDsaSecurityKey : AsymmetricSecurityKey
{
    public EdDsa EdDsa { get; }

    public EdDsaSecurityKey(EdDsa edDsa)
    {
        CryptoProviderFactory.CustomCryptoProvider = new ExtendedCryptoProvider();
        EdDsa = edDsa ?? throw new ArgumentNullException(nameof(edDsa));
    }
    
    public override int KeySize => EdDsa.KeySize;

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
    public override bool HasPrivateKey => EdDsa.Parameters.D != null;

    public override PrivateKeyStatus PrivateKeyStatus
        => EdDsa.Parameters.D != null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
}