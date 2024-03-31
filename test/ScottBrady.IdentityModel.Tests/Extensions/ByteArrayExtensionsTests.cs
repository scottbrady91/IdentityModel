using System;
using System.Linq;
using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Extensions;

public class ByteArrayExtensionsTests
{
    [Fact]
    public void Combine_OneArrays_ExpectCorrectBytes()
    {
        var originalBytes = new byte[] { 1, 2, 3 };

        var result = originalBytes.Combine();

        result.Should().BeEquivalentTo(new byte[] { 1, 2, 3 });
    }
    
    [Fact]
    public void Combine_TwoArrays_ExpectCorrectBytes()
    {
        var originalBytes = new byte[] { 1, 2, 3 };
        var array1 = new byte[] { 4, 5, 6 };

        var result = originalBytes.Combine(array1);

        result.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5, 6 });
    }
    
    [Fact]
    public void Combine_ThreeArrays_ExpectCorrectBytes()
    {
        var originalBytes = new byte[] { 1, 2, 3 };
        var array1 = new byte[] { 4, 5, 6 };
        var array2 = new byte[] { 7, 8, 9 };

        var result = originalBytes.Combine(array1, array2);

        result.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    }

    [Fact]
    public void Combine_RandomArrays_ExpectCorrectBytes()
    {
        var originalBytes = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(3072));
        var array1 = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(3072));
        var array2 = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(3072));

        var result = originalBytes.Combine(array1, array2);

        result.Should().BeEquivalentTo(originalBytes.Concat(array1).Concat(array2));
    }
    
    [Fact]
    public void Combine_WhenParameterIsNull_ExpectArgumentNullException()
    {
        var originalBytes = new byte[] { 1, 2, 3 };

        var act = () => originalBytes.Combine(null);

        act.Should().Throw<ArgumentNullException>();
    }
}