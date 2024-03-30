using System;
using System.Linq;

namespace ScottBrady.IdentityModel;

public static class ByteArrayExtensions // TODO: unit test
{
    /// <summary>
    /// Combines multiple byte arrays.
    /// https://stackoverflow.com/questions/415291/best-way-to-combine-two-or-more-byte-arrays-in-c-sharp
    /// </summary>
    public static byte[] Combine(this byte[] source, params byte[][] arrays)
    {
        var output = new byte[source.Length + arrays.Sum(a => a.Length)];
        Buffer.BlockCopy(source, 0, output, 0, source.Length);

        var offset = source.Length;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, output, offset, array.Length);
            offset += array.Length;
        }

        return output;
    }
}