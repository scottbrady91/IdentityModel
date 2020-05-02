using System;
using System.Globalization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoSecurityToken : JwtPayloadSecurityToken
    {
        internal PasetoSecurityToken() { }

        public PasetoSecurityToken(string payload) : base(payload)
        {
            /*var tokenParts = token.Split('.');
            
            Version = tokenParts[0];
            Purpose = tokenParts[1];
            EncodedPayload = tokenParts[2];
            
            if (token.Length == 4) Footer = tokenParts[3];*/
        }

        public virtual string Version { get; }
        public virtual string Purpose { get; }
        public virtual string EncodedPayload { get; }
        public virtual string Footer { get; }
        
        public override DateTime IssuedAt => ParsePasetoDateTimeClaim(JwtRegisteredClaimNames.Iat);
        public override DateTime ValidFrom => ParsePasetoDateTimeClaim(JwtRegisteredClaimNames.Nbf);
        public override DateTime ValidTo => ParsePasetoDateTimeClaim(JwtRegisteredClaimNames.Exp);

        public override SecurityKey SecurityKey => throw new NotSupportedException();
        public override SecurityKey SigningKey { get; set; }

        public DateTime ParsePasetoDateTimeClaim(string claimType)
        {
            if (InnerToken.TryGetPayloadValue<string>(claimType, out var claimValue))
            {
                // ISO 8601 format
                if (DateTime.TryParse(claimValue, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.RoundtripKind, out var dateTime))
                {
                    return dateTime.ToUniversalTime();
                }
                
                throw new SecurityTokenInvalidLifetimeException($"Unable to parse date time from '{claimType}'. Failing value: '{claimValue}'");
            }

            return DateTime.MinValue;
        }
    }
}