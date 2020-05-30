using System;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Crypto
{
    internal class ExtendedCryptoProvider : ICryptoProvider
    {
        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
            => algorithm == ExtendedSecurityAlgorithms.EdDsa;

        public object Create(string algorithm, params object[] args)
        {
            if (algorithm == ExtendedSecurityAlgorithms.EdDsa && args[0] is EdDsaSecurityKey key)
            {
                return new EdDsaSignatureProvider(key, algorithm);
            }

            throw new NotSupportedException();
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposableObject)
                disposableObject.Dispose();
        }
    }
}