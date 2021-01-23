using System;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.TagHelpers;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Options;
using ScottBrady.IdentityModel.AspNetCore.Configuration;

namespace ScottBrady.IdentityModel.AspNetCore.TagHelpers
{
    /// <summary>
    /// Creates an input element with a type of "password", autocomplete of "new-password",
    /// and transforms ASP.NET Identity password validation rules into the passwordrule attribute.
    /// </summary>
    [HtmlTargetElement("newpassword")]
    public class NewPasswordTagHelper : InputTagHelper
    {
        internal IdentityOptions Options { get; }
        
        /// <summary>
        /// Creates a new <see cref="NewPasswordTagHelper"/>.
        /// </summary>
        /// <param name="generator">The <see cref="IHtmlGenerator"/>.</param>
        /// <param name="optionsAccessor">The <see cref="IdentityOptions"/>.</param>
        public NewPasswordTagHelper(
            IHtmlGenerator generator, 
            IOptions<IdentityOptions> optionsAccessor) : base(generator)
        {
            Options = optionsAccessor?.Value;
        }

        /// <inheritdoc />
        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (output == null) throw new ArgumentNullException(nameof(output));
            
            ProcessInputTag(context, output);

            output.TagName = "input";
            output.Attributes.SetAttribute("type", "password");
            output.Attributes.SetAttribute("autocomplete", "new-password");
            output.Attributes.SetAttribute("autocorrect", "off");
            output.Attributes.SetAttribute("autocapitalize", "off");
            
            ProcessIdentityPasswordRules(Options.Password, output);
        }

        internal virtual void ProcessIdentityPasswordRules(PasswordOptions options, TagHelperOutput output)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (output == null) throw new ArgumentNullException(nameof(output));

            var passwordRules = new StringBuilder();
            passwordRules.AppendFormat("minlength: {0};", options.RequiredLength);
            
            if (options.RequireLowercase) passwordRules.Append(" required: lower;");
            if (options.RequireUppercase) passwordRules.Append(" required: upper;");
            if (options.RequireDigit) passwordRules.Append(" required: digit;");
            if (options.RequireNonAlphanumeric) passwordRules.Append(" required: [-().&@?'#,/&quot;+];");
            
            output.Attributes.SetAttribute("passwordrules", passwordRules.ToString());
            output.Attributes.SetAttribute("minlength", options.RequiredLength);
        }

        internal virtual void ProcessInputTag(TagHelperContext context, TagHelperOutput output)
            => base.Process(context, output);
    }
}