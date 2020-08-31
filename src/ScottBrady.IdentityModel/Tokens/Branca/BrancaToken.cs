using System;

namespace ScottBrady.IdentityModel.Tokens
{
    public class BrancaToken
    {
        private static readonly DateTime MinDateTime = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc);
        private static readonly DateTime MaxDateTime = new DateTime(2106, 02, 07, 06, 28, 15, DateTimeKind.Utc);
        
        public BrancaToken(string payload, uint timestamp)
        {
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
            Timestamp = GetDateTime(timestamp);
            BrancaFormatTimestamp = timestamp;
        }
        
        public string Payload { get; }
        public DateTime Timestamp { get; }
        public uint BrancaFormatTimestamp { get; }

        public static DateTime GetDateTime(uint timestamp)
        {
            return DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;
        }

        public static uint GetBrancaTimestamp(DateTimeOffset dateTime)
        {            
            if (dateTime < MinDateTime || MaxDateTime < dateTime)
                throw new InvalidOperationException("Timestamp cannot be before 1970 or after 2106 (uint max)");

            return Convert.ToUInt32(dateTime.ToUniversalTime().ToUnixTimeSeconds());
        }
    }
}