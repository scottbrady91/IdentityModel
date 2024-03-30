using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

namespace ScottBrady.IdentityModel.Tests;

public class Base62Tests
{
    [Theory]
    [InlineData("t", "1s")]
    [InlineData("te", "7kb")]
    [InlineData("tes", "W0Qd")]
    [InlineData("test", "289lyu")]
    [InlineData("test_", "8ngM7Ul")]
    [InlineData("test_v", "aL8tKx1y")]
    [InlineData("test_va", "2Q3IiUVk9J")]
    [InlineData("test_val", "9zZdHhz4YSC")]
    public void WithKnownValues_ExpectCorrectValuesEncoded(string testValue, string expectedResult)
    {
            var testBytes = Encoding.UTF8.GetBytes(testValue);
            
            var result = Base62.Encode(testBytes);
            result.Should().Be(expectedResult);

            var decodedBytes = Base62.Decode(result);
            decodedBytes.Should().BeEquivalentTo(testBytes);
        }

    [Theory]
    [InlineData("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ", "Z2OiyFrg9j5RTozitQyWlPIpRF9zciF7WUm0omCp8p8amBsp3T7z3XtHx9aAcgG5J5ggJT7mLQP1WonC0PAUF7hrM4KT6dwoUqhBsRWHBS3gZXeCkIbJP")]
    [InlineData("¥·£·€·$·¢·₡·₢·₣·₤·₥·₦·₧·₨·₩·₪·₫·₭·₮·₯·₹", "cyHYeZmwVtcfi8uomwZ9VTrEews1tZEkwNsVEOzPtGnuTpxFrKkQykOshm9OCqSa0YkPX13Js2w8QAcKpHsMHzdKzNG9htLkL6Pu6xFSwoSZycE8aUfGRIZTKcX8L")]
    public void WithUtf8Characters_ExpectCorrectValuesEncoded(string testValue, string expectedResult)
    {
            var testBytes = Encoding.UTF8.GetBytes(testValue);
            
            var result = Base62.Encode(testBytes);
            result.Should().Be(expectedResult);

            var decodedBytes = Base62.Decode(result);
            decodedBytes.Should().BeEquivalentTo(testBytes);
        }

    [Fact]
    public void WithRandomBytes_ExpectCorrectValuesEncoded()
    {
            var bytes = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            var encodedBytes = Base62.Encode(bytes);
            Base62.Decode(encodedBytes).Should().BeEquivalentTo(bytes);
        }
}