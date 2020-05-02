using System.IO;

namespace ScottBrady.IdentityModel.Extensions
{
    public static class StreamExtensions
    {
        public static bool TryRead(this Stream stream, int length, out byte[] bytes)
        {
            bytes = new byte[length];
            var bytesRead = stream.Read(bytes, 0, length);

            if (bytesRead != length) return false;
            return true;
        }
    }
}