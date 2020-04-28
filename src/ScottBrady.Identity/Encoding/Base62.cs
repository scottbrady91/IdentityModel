using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ScottBrady.Identity
{
    /// <summary>
    /// Adapted from https://github.com/ghost1face/base62
    /// </summary>
    public static class Base62
    {
        public const string CharacterSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        public static string Encode(byte[] value)
        {
            var convertedBytes = BaseConvert(value, 256, 62);
            
            var builder = new StringBuilder();
            foreach (var b in convertedBytes)
            {
                builder.Append(CharacterSet[b]);
            }
            
            return builder.ToString();
        }

        public static byte[] Decode(string value)
        {
            var arr = new byte[value.Length];
            for (var i = 0; i < arr.Length; i++)
            {
                arr[i] = (byte)CharacterSet.IndexOf(value[i]);
            }

            return BaseConvert(arr, 62, 256);
        }
        
        private static byte[] BaseConvert(byte[] source, int sourceBase, int targetBase)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            
            int count;
            var result = new List<int>();
            
            while ((count = source.Length) > 0)
            {
                var remainder = 0;
                var quotients = new List<byte>();
                
                for (var i = 0; i != count; i++)
                {
                    var accumulator = source[i] + remainder * sourceBase;
                    var quotient = Math.DivRem(accumulator, targetBase, out remainder);
                    
                    if (quotients.Count > 0 || quotient != 0) quotients.Add((byte) quotient);
                }

                result.Insert(0, remainder);
                source = quotients.ToArray();
            }

            return result.Select(x => (byte) x).ToArray();
        }
    }
}