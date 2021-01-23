using Microsoft.AspNetCore.Identity;

namespace ScottBrady.IdentityModel.AspNetCore.Identity
{
    public class ExtendedPasswordOptions : PasswordOptions
    {
        public int? MaxLength { get; set; }
        public int? MaxConsecutiveChars { get; set; }
    }
}