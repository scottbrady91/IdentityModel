using System;
using System.Globalization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoSecurityToken : JwtPayloadSecurityToken
    {
        public PasetoSecurityToken(PasetoToken token) : base(token.Payload)
        {
            Version = token.Version;
            Purpose = token.Purpose;
            Footer = token.Footer;

            RawToken = token.RawToken;
        }

        public virtual string Version { get; }
        public virtual string Purpose { get; }
        public virtual string Footer { get; }
        public virtual string RawToken { get; }
        
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