using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ScottBrady.Identity.Tokens
{
    public static class JwtPayloadExtensions
    {
        /// <summary>
        /// Creates a JWT payload from a SecurityTokenDescriptor.
        /// Inspired by logic found in Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler
        /// </summary>
        public static string ToJwtPayload(this SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null) throw new ArgumentNullException(nameof(tokenDescriptor));
            
            JObject payload;
            if (tokenDescriptor.Subject != null)
            {
                payload = JObject.FromObject(ToJwtClaimDictionary(tokenDescriptor.Subject.Claims));
            }
            else
            {
                payload = new JObject();
            }
            
            if (tokenDescriptor.Claims != null && tokenDescriptor.Claims.Count > 0)
            {
                payload.Merge(JObject.FromObject(tokenDescriptor.Claims), new JsonMergeSettings {MergeArrayHandling = MergeArrayHandling.Replace});
            }

            if (tokenDescriptor.Issuer != null)
                payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Iss, tokenDescriptor.Issuer);
            if (tokenDescriptor.Audience != null)
                payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Aud, tokenDescriptor.Audience);

            var now = EpochTime.GetIntDate(DateTime.UtcNow);
            
            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Exp,
                tokenDescriptor.Expires.HasValue 
                    ? EpochTime.GetIntDate(tokenDescriptor.Expires.Value)
                    : now + TimeSpan.FromMinutes(60).TotalSeconds);
            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Iat, 
                tokenDescriptor.IssuedAt.HasValue
                ? EpochTime.GetIntDate(tokenDescriptor.IssuedAt.Value)
                : now);
            payload.AddClaimIfNotPresent(JwtRegisteredClaimNames.Nbf, 
                tokenDescriptor.NotBefore.HasValue
                ? EpochTime.GetIntDate(tokenDescriptor.NotBefore.Value)
                : now);
            
            return payload.ToString(Formatting.None);
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

        private static void AddClaimIfNotPresent(this JObject payload, string type, JToken value)
        {
            if (payload.TryGetValue(type, StringComparison.Ordinal, out var _)) return;
            payload[type] = value;
        }
    }
}