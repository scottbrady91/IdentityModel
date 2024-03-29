using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

namespace ScottBrady.IdentityModel.Tests;

public class Base16Tests
{
    [Theory]
    [InlineData("t", "74")]
    [InlineData("te", "7465")]
    [InlineData("tes", "746573")]
    [InlineData("test", "74657374")]
    [InlineData("test_", "746573745f")]
    [InlineData("test_v", "746573745f76")]
    [InlineData("test_va", "746573745f7661")]
    [InlineData("test_val", "746573745f76616c")]
    public void WithKnownValues_ExpectCorrectValuesEncoded(string testValue, string expectedResult)
    {
            var testBytes = Encoding.UTF8.GetBytes(testValue);
            
            var result = Base16.Encode(testBytes);
            result.Should().Be(expectedResult);

            var decodedBytes = Base16.Decode(result);
            decodedBytes.Should().BeEquivalentTo(testBytes);
        }
        

    [Theory]
    [InlineData("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ", "e19aa0e19b87e19abbe19babe19b92e19ba6e19aa6e19babe19aa0e19ab1e19aa9e19aa0e19aa2e19ab1e19babe19aa0e19b81e19ab1e19aaae19babe19ab7e19b96e19abbe19ab9e19ba6e19b9ae19ab3e19aa2e19b97")]
    [InlineData("¥·£·€·$·¢·₡·₢·₣·₤·₥·₦·₧·₨·₩·₪·₫·₭·₮·₯·₹", "c2a5c2b7c2a3c2b7e282acc2b724c2b7c2a2c2b7e282a1c2b7e282a2c2b7e282a3c2b7e282a4c2b7e282a5c2b7e282a6c2b7e282a7c2b7e282a8c2b7e282a9c2b7e282aac2b7e282abc2b7e282adc2b7e282aec2b7e282afc2b7e282b9")]
    public void WithUtf8Characters_ExpectCorrectValuesEncoded(string testValue, string expectedResult)
    {
            var testBytes = Encoding.UTF8.GetBytes(testValue);
            
            var result = Base16.Encode(testBytes);
            result.Should().Be(expectedResult);

            var decodedBytes = Base16.Decode(result);
            decodedBytes.Should().BeEquivalentTo(testBytes);
        }

    [Fact]
    public void WithRandomBytes_ExpectCorrectValuesEncoded()
    {
            var bytes = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            var encodedBytes = Base16.Encode(bytes);
            Base16.Decode(encodedBytes).Should().BeEquivalentTo(bytes);
        }
}