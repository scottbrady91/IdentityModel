using System;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

namespace ScottBrady.IdentityModel.Tokens
{
    public class EdDsaSecurityKey : AsymmetricSecurityKey
    {
        public EdDsaSecurityKey(Ed25519PublicKeyParameters keyParameters)
        {
            KeyParameters = keyParameters ?? throw new ArgumentNullException(nameof(keyParameters));
        }
        
        public virtual Ed25519PublicKeyParameters KeyParameters { get; }
        public override int KeySize => throw new NotImplementedException();
        
        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey => KeyParameters.IsPrivate;

        public override PrivateKeyStatus PrivateKeyStatus
            => KeyParameters.IsPrivate ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
    }
}