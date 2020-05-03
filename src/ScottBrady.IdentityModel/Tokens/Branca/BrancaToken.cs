using System;

namespace ScottBrady.IdentityModel.Tokens
{
    public class BrancaToken
    {
        public BrancaToken(string payload, uint timestamp)
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
            Timestamp = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
        }
        
        public string Payload { get; }
        public DateTime Timestamp { get; }
    }
}