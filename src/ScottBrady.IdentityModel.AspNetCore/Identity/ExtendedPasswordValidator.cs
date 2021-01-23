using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace ScottBrady.IdentityModel.AspNetCore.Identity
{
    /// <summary>
    /// Extends the base ASP.NET Core Identity PasswordValidator with max length and max consecutive character checks.
    /// </summary>
    public class ExtendedPasswordValidator<TUser> : PasswordValidator<TUser> where TUser : class
    {
        public ExtendedPasswordValidator(IdentityErrorDescriber errors = null) : base(errors) { }

        /// <summary>
        /// Checks the base password validation rules and, if configured, max length and max consecutive characters.
        /// </summary>
        public override async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            if (manager == null) throw new ArgumentNullException(nameof(manager));
            if (password == null) throw new ArgumentNullException(nameof(password));
            
            var result = await BaseValidate(manager, user, password);

            var errors = result.Errors.ToList();
            
            if (manager.Options.Password is ExtendedPasswordOptions options)
            {
                if (options.MaxLength.HasValue && 0 < options.MaxLength && options.MaxLength < password.Length)
                {
                    errors.Add(new IdentityError {Code = "0", Description = ""});
                }

                if (options.MaxConsecutiveChars.HasValue 
                    && 0 <= options.MaxConsecutiveChars 
                    && HasConsecutiveCharacters(password, options.MaxConsecutiveChars.Value))
                {
                    errors.Add(new IdentityError {Code = "0", Description = ""});
                }
            }

            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }
        
        /// <summary>
        /// Checks for consecutive characters using Regex.
        /// Does not account for UTF16 surrogate pairs.
        /// Adapted from https://codereview.stackexchange.com/questions/102568/checking-if-a-text-contains-n-consecutive-repeating-characters
        /// </summary>
        public virtual bool HasConsecutiveCharacters(string password, int maxConsecutive)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            
            var max = maxConsecutive;
            if (max <= 0) max = 1;
            
            return Regex.IsMatch(password,"(.)\\1{"+ max + "}");
        }

        internal virtual Task<IdentityResult> BaseValidate(UserManager<TUser> manager, TUser user, string password) 
            => base.ValidateAsync(manager, user, password);
    }
}