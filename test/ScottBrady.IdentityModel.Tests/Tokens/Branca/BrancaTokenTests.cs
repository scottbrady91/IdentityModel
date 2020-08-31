using System;
using FluentAssertions;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    public class BrancaTokenTests
    {
        [Fact]
        public void ctor_ExpectPayloadSet()
        {
            const string payload = "89f7baaee2ab476483d45b945f79d6af";

            var token = new BrancaToken(payload, uint.MaxValue);

            token.Payload.Should().Be(payload);
        }

        [Fact]
        public void ctor_WhenTimestampIsZero_ExpectUnixTimeStart()
        {
            const uint timestamp = 0;

            var token = new BrancaToken("test", 0);

            token.Timestamp.Should().Be(new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc));
            token.BrancaFormatTimestamp.Should().Be(timestamp);
        }

        [Fact]
        public void ctor_WhenTimestampIs27November_ExpectCorrectDateTime()
        {
            const uint timestamp = 123206400;
            
            var token = new BrancaToken("test", timestamp);

            token.Timestamp.Should().Be(new DateTime(1973, 11, 27, 0, 0, 0, DateTimeKind.Utc));
            token.BrancaFormatTimestamp.Should().Be(timestamp);
        }

        [Fact]
        public void ctor_WhenTimestampIsMaxValue_ExpectCorrectDateTime()
        {
            const uint timestamp = uint.MaxValue;
            
            var token = new BrancaToken("test", timestamp);

            token.Timestamp.Should().Be(new DateTime(2106, 02, 07, 06, 28, 15, DateTimeKind.Utc));
            token.BrancaFormatTimestamp.Should().Be(timestamp);
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