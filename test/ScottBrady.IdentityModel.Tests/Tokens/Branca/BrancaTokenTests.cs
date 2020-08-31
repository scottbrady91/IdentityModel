using System;
using FluentAssertions;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    public class BrancaTokenTests
    {
        [Fact]
        public void ctor_ExpectPropertiesSet()
        {
            const string payload = "89f7baaee2ab476483d45b945f79d6af";
            const uint timestamp = uint.MinValue;

            var token = new BrancaToken(payload, timestamp);

            token.Payload.Should().Be(payload);
            token.BrancaFormatTimestamp.Should().Be(timestamp);
            token.Timestamp.Should().Be(new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc));
        }

        [Fact]
        public void GetDateTime_WhenTimestampIsZero_ExpectUnixTimeStart()
        {
            const uint timestamp = 0;

            var dateTime = BrancaToken.GetDateTime(timestamp);

            dateTime.Should().Be(new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc));
        }

        [Fact]
        public void GetDateTime_WhenTimestampIs27November_ExpectCorrectDateTime()
        {
            const uint timestamp = 123206400;
            
            var dateTime = BrancaToken.GetDateTime(timestamp);

            dateTime.Should().Be(new DateTime(1973, 11, 27, 0, 0, 0, DateTimeKind.Utc));
        }

        [Fact]
        public void GetDateTime_WhenTimestampIsMaxValue_ExpectCorrectDateTime()
        {
            const uint timestamp = uint.MaxValue;
            
            var dateTime = BrancaToken.GetDateTime(timestamp);

            dateTime.Should().Be(new DateTime(2106, 02, 07, 06, 28, 15, DateTimeKind.Utc));
        }

        [Fact]
        public void GetBrancaTimestamp_WhenDateBeforeUnixTimeStart_ExpectException()
        {
            Assert.Throws<InvalidOperationException>(()
                => BrancaToken.GetBrancaTimestamp(new DateTime(1969, 01, 01)));
        }

        [Fact]
        public void GetBrancaTimestamp_WhenUnixTimeStart_ExpectZero()
        {
            var timestamp = BrancaToken.GetBrancaTimestamp(new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc));

            timestamp.Should().Be(uint.MinValue);
        }

        [Fact]
        public void GetBrancaTimestamp_When27November_ExpectZero()
        {
            var timestamp = BrancaToken.GetBrancaTimestamp(new DateTime(1973, 11, 27, 0, 0, 0, DateTimeKind.Utc));

            timestamp.Should().Be(123206400);
        }

        [Fact]
        public void GetBrancaTimestamp_WhenMaxTimestamp_ExpectUintMax()
        {
            var timestamp = BrancaToken.GetBrancaTimestamp(new DateTime(2106, 02, 07, 06, 28, 15, DateTimeKind.Utc));

            timestamp.Should().Be(uint.MaxValue);
        }

        [Fact]
        public void GetBrancaTimestamp_WhenAfterMaxTimestamp_ExpectInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() 
                => BrancaToken.GetBrancaTimestamp(new DateTime(2106, 02, 07, 06, 28, 16, DateTimeKind.Utc)));
        }
    }
}