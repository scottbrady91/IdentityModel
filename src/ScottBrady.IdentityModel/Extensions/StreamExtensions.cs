using System.IO;

namespace ScottBrady.IdentityModel;

public static class StreamExtensions
{
    /// <summary>
    /// Safely read the next x bytes from a stream.
    /// </summary>
    public static bool TryRead(this Stream stream, int length, out byte[] bytes)
    {
        bytes = new byte[length];
        var bytesRead = stream.Read(bytes, 0, length);

        if (bytesRead != length) return false;
        return true;
    }
}