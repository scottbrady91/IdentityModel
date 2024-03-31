using System.IO;
using System.Linq;
using FluentAssertions;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Extensions;

public class StreamExtensionsTests
{
    [Fact]
    public void TryRead_WhenStreamHasEnoughBytes_ExpectTrueWithCorrectBytes()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        var result = new MemoryStream(bytes).TryRead(3, out var readBytes);

        result.Should().BeTrue();
        readBytes.Should().BeEquivalentTo(bytes[..3]);
        readBytes.Should().NotBeSameAs(bytes);
    }
    
    [Fact]
    public void TryRead_WhenStreamDoesNotHaveEnoughBytes_ExpectFalseWithPartiallyFilledByteArray()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        var result = new MemoryStream(bytes).TryRead(6, out var readBytes);

        result.Should().BeFalse();
        readBytes.Should().BeEquivalentTo(bytes.Concat(new byte[] { 0 }));
    }
}