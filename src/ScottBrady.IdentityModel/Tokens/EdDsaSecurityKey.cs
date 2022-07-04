using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens
{
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

        public EdDsaSecurityKey(EdDsa edDsa) : this()
        {
            EdDsa = edDsa ?? throw new ArgumentNullException(nameof(edDsa));
        }
        
        [Obsolete("Deprecated in favor of EdDsa constructor")]
        public EdDsaSecurityKey(Ed25519PrivateKeyParameters keyParameters) : this()
        {
            if (keyParameters == null) throw new ArgumentNullException(nameof(keyParameters));
            EdDsa = EdDsa.CreateFromPrivateKey(keyParameters.GetEncoded(), ExtendedSecurityAlgorithms.Curves.Ed25519);
        }

        [Obsolete("Deprecated in favor of EdDsa constructor")]
        public EdDsaSecurityKey(Ed25519PublicKeyParameters keyParameters) : this()
        {
            if (keyParameters == null) throw new ArgumentNullException(nameof(keyParameters));
            EdDsa = EdDsa.CreateFromPublicKey(keyParameters.GetEncoded(), ExtendedSecurityAlgorithms.Curves.Ed25519);
        }
        
        public override int KeySize => throw new NotImplementedException();
        
        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey => EdDsa.KeyParameters.IsPrivate;

        public override PrivateKeyStatus PrivateKeyStatus
            => EdDsa.KeyParameters.IsPrivate ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
    }
}