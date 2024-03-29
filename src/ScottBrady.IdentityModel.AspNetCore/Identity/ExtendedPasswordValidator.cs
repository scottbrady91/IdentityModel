using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace ScottBrady.IdentityModel.AspNetCore.Identity;

/// <summary>
/// ASP.NET Core Identity PasswordValidator for max length and max consecutive character checks.
/// </summary>
public class ExtendedPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
{
    /// <summary>
    /// Validates the password for max length and max consecutive characters.
    /// </summary>
    public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
    {
        if (manager == null) throw new ArgumentNullException(nameof(manager));
        if (password == null) throw new ArgumentNullException(nameof(password));
            
        var errors = new List<IdentityError>();
            
        if (manager.Options.Password is ExtendedPasswordOptions options)
        {
            if (options.MaxLength.HasValue && 0 < options.MaxLength && options.MaxLength < password.Length)
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordTooLong", 
                    Description = $"Passwords must be no longer than {options.MaxLength} characters"
                });
            }

            if (options.MaxConsecutiveChars.HasValue 
                && 0 <= options.MaxConsecutiveChars 
                && HasConsecutiveCharacters(password, options.MaxConsecutiveChars.Value))
            {
                errors.Add(new IdentityError
                {
                    Code = "TooManyConsecutiveCharacters",
                    Description = $"Password must not contain more than {options.MaxConsecutiveChars} consecutive characters"
                });
            }
        }

        return Task.FromResult(errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray()));
    }
        
    /// <summary>
    /// Checks for consecutive characters using Regex.
    /// Does not account for UTF16 surrogate pairs.
    /// Adapted from https://codereview.stackexchange.com/questions/102568/checking-if-a-text-contains-n-consecutive-repeating-characters
    /// </summary>
    public virtual bool HasConsecutiveCharacters(string password, int maxConsecutive)
    {
        if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));
            
        var invalidAmount = 1;
        if (1 < maxConsecutive) invalidAmount = maxConsecutive;
            
        return Regex.IsMatch(password,"(.)\\1{"+ invalidAmount + "}");
    }
}