using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel;

public static class ExtendedJsonWebKeyConverter
{
    public static JsonWebKey ConvertFromEdDsaSecurityKey(EdDsaSecurityKey key)
    {
        
        var parameters = key.EdDsa.Parameters;
        return new JsonWebKey
        {
            Crv = parameters.Curve,
            X = parameters.X != null ? Base64UrlEncoder.Encode(parameters.X) : null,
            D = parameters.D != null ? Base64UrlEncoder.Encode(parameters.D) : null,
            Kty = ExtendedSecurityAlgorithms.KeyTypes.Ecdh,
            Alg = ExtendedSecurityAlgorithms.EdDsa,
            CryptoProviderFactory = key.CryptoProviderFactory,
        };
    }

    public static bool TryConvertToEdDsaSecurityKey(JsonWebKey webKey, out EdDsaSecurityKey key)
    {
        key = null;
        
        if (webKey != null && webKey.Kty == ExtendedSecurityAlgorithms.KeyTypes.Ecdh)
        {
            if (webKey.Crv == ExtendedSecurityAlgorithms.Curves.Ed25519
                || webKey.Crv == ExtendedSecurityAlgorithms.Curves.Ed448)
            {
                try
                {
                    key = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(webKey.Crv)
                    {
                        X = webKey.X != null ? Base64UrlEncoder.DecodeBytes(webKey.X) : null,
                        D = webKey.D != null ? Base64UrlEncoder.DecodeBytes(webKey.D) : null
                    }));
                    
                    return true;
                }
                catch (Exception ex)
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant("Unable to create an EdDsaSecurityKey from the properties found in the JsonWebKey: '{0}', Exception '{1}'.", webKey, ex));
                }
                
            }
        }

        return false;
    }
}