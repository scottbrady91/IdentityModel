using Microsoft.AspNetCore.Identity;

namespace ScottBrady.IdentityModel.AspNetCore.Identity
{
    /// <summary>
    /// Extends <see cref="PasswordOptions"/> to support all passwordrules attribute values.
    /// </summary>
    public class ExtendedPasswordOptions : PasswordOptions
    {
        /// <summary>
        /// The maximum length of the password.
        /// </summary>
        public int? MaxLength { get; set; }
        
        /// <summary>
        /// The maximum number of consecutive identical characters allowed in the password.
        /// </summary>
        public int? MaxConsecutiveChars { get; set; }
    }
}