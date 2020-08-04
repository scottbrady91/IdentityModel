using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens
{
    public class EdDsaSecurityKey : AsymmetricSecurityKey
    {
        private EdDsaSecurityKey()
        {
            CryptoProviderFactory.CustomCryptoProvider = new ExtendedCryptoProvider();
        }

        // TODO: Deprecate leaky abstraction
        public EdDsaSecurityKey(Ed25519PrivateKeyParameters keyParameters) : this()
        {
            KeyParameters = keyParameters ?? throw new ArgumentNullException(nameof(keyParameters));
            Curve = ExtendedSecurityAlgorithms.Curves.Ed25519;
        }

        public EdDsaSecurityKey(Ed25519PublicKeyParameters keyParameters) : this()
        {
            KeyParameters = keyParameters ?? throw new ArgumentNullException(nameof(keyParameters));
            Curve = ExtendedSecurityAlgorithms.Curves.Ed25519;
        }
        
        public virtual AsymmetricKeyParameter KeyParameters { get; }
        public string Curve { get; }
        
        public override int KeySize => throw new NotImplementedException();
        
        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey => KeyParameters.IsPrivate;

        public override PrivateKeyStatus PrivateKeyStatus
            => KeyParameters.IsPrivate ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
    }
}