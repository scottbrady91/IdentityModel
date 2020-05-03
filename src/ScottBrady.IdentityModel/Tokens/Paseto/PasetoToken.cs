using System;
using Newtonsoft.Json.Linq;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoToken
    {
        public PasetoToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentNullException(nameof(token));
            
            var tokenParts = token.Split(new[] {'.'}, PasetoConstants.MaxPasetoSegmentCount + 1);
            if (tokenParts.Length != 3 && tokenParts.Length != 4) throw new ArgumentException("Invalid number of token segments");
            
            RawToken = token;

            Version = tokenParts[0];
            Purpose = tokenParts[1];
            EncodedPayload = tokenParts[2];
            if (tokenParts.Length == 4) Footer = tokenParts[3];
        }
        
        public string RawToken { get; }
        
        public string Version { get; }
        public string Purpose { get; }
        public string Footer { get; }
        
        public string EncodedPayload { get; }
        public JObject Payload { get; private set; }

        public void SetPayload(string payload)
        {
            if (string.IsNullOrWhiteSpace(payload)) throw new ArgumentNullException(nameof(payload));
            
            try
            {
                Payload = JObject.Parse(payload);
            }
            catch (Exception e)
            {
                throw new ArgumentException("Token does contain valid JSON", e);
            }
        }
    }
}