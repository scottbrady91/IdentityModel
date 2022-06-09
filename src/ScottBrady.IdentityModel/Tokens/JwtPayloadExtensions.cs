using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public static class JwtPayloadExtensions
    {
        /// <summary>
        /// Creates a JWT payload from a SecurityTokenDescriptor.
        /// Inspired by logic found in Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler
        /// </summary>
        public static string ToJwtPayload(this SecurityTokenDescriptor tokenDescriptor, JwtDateTimeFormat dateTimeFormat = JwtDateTimeFormat.Unix)
        {
            if (tokenDescriptor == null) throw new ArgumentNullException(nameof(tokenDescriptor));
            
            Dictionary<string, object> payload;
            if (tokenDescriptor.Subject != null)
            {
                payload = ToJwtClaimDictionary(tokenDescriptor.Subject.Claims);
            }
            else
            {
                payload = new Dictionary<string, object>();
            }
            
            if (tokenDescriptor.Claims != null && tokenDescriptor.Claims.Count > 0)
            {
                foreach (var pair in tokenDescriptor.Claims)
                    payload[pair.Key] = pair.Value;
            }

            if (tokenDescriptor.Issuer != null)
                payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Iss, tokenDescriptor.Issuer);
            if (tokenDescriptor.Audience != null)
                payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Aud, tokenDescriptor.Audience);

            Func<DateTime?, DateTime, object> dateTimeFormatFunc = null;
            if (dateTimeFormat == JwtDateTimeFormat.Unix) dateTimeFormatFunc = GetUnixClaimValueOrDefault;
            if (dateTimeFormat == JwtDateTimeFormat.Iso) dateTimeFormatFunc = GetIsoClaimValueOrDefault;
            if (dateTimeFormatFunc == null) throw new NotSupportedException("Unsupported DateTime formatting type");
            
            var now = DateTime.UtcNow;

            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Exp, dateTimeFormatFunc(tokenDescriptor.Expires, now.AddMinutes(60)));
            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Iat, dateTimeFormatFunc(tokenDescriptor.IssuedAt, now));
            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Nbf, dateTimeFormatFunc(tokenDescriptor.NotBefore, now));

            return JsonSerializer.Serialize(payload);
        }

        /// <summary>
        /// Handling for serializing claims in a ClaimsIdentity.
        /// Adapted from Microsoft.IdentityModel.JsonWebTokens.JwtTokenUtilities.CreateDictionaryFromClaims
        /// </summary>
        public static Dictionary<string, object> ToJwtClaimDictionary(IEnumerable<Claim> claims)
        {
            var payload = new Dictionary<string, object>();

            foreach (var claim in claims)
            {
                if (claim == null) continue;

                if (payload.TryGetValue(claim.Type, out var existingValue))
                {
                    var existingValues = existingValue as IList<object>;
                    
                    if (existingValues == null)
                    {
                        existingValues = new List<object>();
                        existingValues.Add(existingValue);
                    }
                    
                    existingValues.Add(claim.Value);
                    payload[claim.Type] = existingValues;
                }
                else
                {
                    payload[claim.Type] = claim.Value;
                }
            }

            return payload;
        }

        private static void AddClaimIfNotPresent(this Dictionary<string, object> payload, string type, object value)
        {
            if (payload.TryGetValue(type, out _)) return;
            payload[type] = value;
        }

        private static Func<DateTime?, DateTime, object> GetUnixClaimValueOrDefault
            => (value, defaultValue) => value.HasValue
                ? EpochTime.GetIntDate(value.Value)
                : EpochTime.GetIntDate(defaultValue);
        
        private static Func<DateTime?, DateTime, object> GetIsoClaimValueOrDefault
            => (value, defaultValue) => value.HasValue
                ? value.Value.ToString("yyyy-MM-ddTHH:mm:sszzz")
                : defaultValue.ToString("yyyy-MM-ddTHH:mm:sszzz");
    }

    public enum JwtDateTimeFormat
    {
        Unix,
        Iso
    } 
}