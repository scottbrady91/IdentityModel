using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Options;
using Moq;
using ScottBrady.IdentityModel.AspNetCore.Identity;
using ScottBrady.IdentityModel.AspNetCore.TagHelpers;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.AspNetCore.TagHelpers
{
    public class NewPasswordTagHelperTests
    {
        private readonly Mock<IHtmlGenerator> mockHtmlGenerator = new Mock<IHtmlGenerator>();
        private Mock<IOptions<IdentityOptions>> mockOptionsAccessor = new Mock<IOptions<IdentityOptions>>();

        private readonly TagHelperContext testContext = new TagHelperContext("newpassword", new TagHelperAttributeList(), new Dictionary<object, object>(), "123");
        private readonly TagHelperOutput testOutput = new TagHelperOutput("newpassword", new TagHelperAttributeList(), (b, encoder) => Task.FromResult<TagHelperContent>(new DefaultTagHelperContent()));

        public NewPasswordTagHelperTests()
        {
            mockOptionsAccessor.Setup(x => x.Value).Returns(new IdentityOptions());
            
        }
        
        private NewPasswordTagHelper CreateSut()
        {
            return new NewPasswordTagHelper(mockHtmlGenerator?.Object, mockOptionsAccessor?.Object);
        }
        
        private Mock<NewPasswordTagHelper> CreateMockedSut()
        {
            var sut = new Mock<NewPasswordTagHelper>(mockHtmlGenerator?.Object, mockOptionsAccessor?.Object) {CallBase = true};
            sut.Setup(x => x.ProcessInputTag(It.IsAny<TagHelperContext>(), It.IsAny<TagHelperOutput>()));
            sut.Setup(x => x.ProcessIdentityPasswordRules(It.IsAny<PasswordOptions>(), It.IsAny<TagHelperOutput>()));
            return sut;
        }

        [Fact]
        public void ctor_WhenOptionsAccessorIsNull_ExpectNullOptions()
        {
            mockOptionsAccessor = null;
            var sut = CreateSut();
            sut.Options.Should().BeNull();
        }

        [Fact]
        public void ctor_WhenOptionsAccessorReturnsNullIsNull_ExpectNullOptions()
        {
            mockOptionsAccessor.Setup(x => x.Value).Returns<IdentityOptions>(null);
            var sut = CreateSut();
            sut.Options.Should().BeNull();
        }
        
        [Fact]
        public void Process_WhenTagHelperContextIsNull_ExpectArgumentNullException()
        {
            var sut = CreateMockedSut();
            Assert.Throws<ArgumentNullException>(() => sut.Object.Process(null, testOutput));
        }
        [Fact]
        public void Process_WhenTagHelperOutputIsNull_ExpectArgumentNullException()
        {
            var sut = CreateMockedSut();
            Assert.Throws<ArgumentNullException>(() => sut.Object.Process(testContext, null));
        }

        [Fact]
        public void Process_ExpectExistingAttributesUnmodified()
        {
            testOutput.Attributes.SetAttribute("name", "password");
            testOutput.Attributes.SetAttribute("aria-label", "Password");
            testOutput.Attributes.SetAttribute("required", "required");
            
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            
            testOutput.Attributes["name"].Value.Should().Be("password");
            testOutput.Attributes["aria-label"].Value.Should().Be("Password");
            testOutput.Attributes["required"].Value.Should().Be("required");
        }

        [Fact]
        public void Process_ExpectInputTag()
        {
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            testOutput.TagName.Should().Be("input");
        }

        [Fact]
        public void Process_ExpectTypeOfPassword()
        {
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            testOutput.Attributes["type"].Value.Should().Be("password");
        }

        [Fact]
        public void Process_WithExistingType_ExpectTypeOfPassword()
        {
            testOutput.Attributes.SetAttribute("type", "text");
            
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            
            testOutput.Attributes["type"].Value.Should().Be("password");
        }

        [Fact]
        public void Process_ExpectAutoCompleteOfNewPassword()
        {
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            testOutput.Attributes["autocomplete"].Value.Should().Be("new-password");
        }

        [Fact]
        public void Process_ExpectAutoCorrectDisabled()
        {
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            testOutput.Attributes["autocorrect"].Value.Should().Be("off");
        }

        [Fact]
        public void Process_ExpectAutoCapitalizeDisabled()
        {
            var sut = CreateMockedSut();
            sut.Object.Process(testContext, testOutput);
            testOutput.Attributes["autocapitalize"].Value.Should().Be("off");
        }

        [Fact]
        public void ProcessIdentityPasswordRules_WhenOptionsAreNull_ExpectArgumentNullException()
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.ProcessIdentityPasswordRules(null, testOutput));
        }

        [Fact]
        public void ProcessIdentityPasswordRules_WhenTagHelperOutputIsNull_ExpectArgumentNullException()
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.ProcessIdentityPasswordRules(new PasswordOptions(), null));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(6)]
        [InlineData(42)]
        [InlineData(255)]
        public void ProcessIdentityPasswordRules_ExpectCorrectRequiredLengthAttributes(int expectedMinLength)
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequiredLength = expectedMinLength};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain($"minlength: {expectedMinLength};");
            testOutput.Attributes["minlength"].Value.Should().Be(expectedMinLength);
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireLowercaseIsTrue_ExpectRequiredLowerAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireLowercase = true};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain("required: lower;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireLowercaseIsFalse_ExpectNoRequiredLowerAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireLowercase = false};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("required: lower;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireUppercaseIsTrue_ExpectRequiredUpperAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireUppercase = true};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain("required: upper;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireUppercaseIsFalse_ExpectNoRequiredUpperAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireUppercase = false};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("required: upper;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireDigitIsTrue_ExpectRequiredDigitAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireDigit = true};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain("required: digit;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireDigitIsFalse_ExpectNoRequiredDigitAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireDigit = false};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("required: digit;");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireNonAlphanumericIsTrue_ExpectRequiredCharactersAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireNonAlphanumeric = true};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain("required: [-().&@?'#,/&quot;+];");
        }
        
        [Fact]
        public void ProcessIdentityPasswordRules_WhenRequireNonAlphanumericIsFalse_ExpectNoRequiredCharactersAttribute()
        {
            var sut = CreateSut();
            var options = new PasswordOptions {RequireNonAlphanumeric = false};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("required: [");
        }

        [Fact]
        public void ProcessIdentityPasswordRules_WhenExtendedOptionsWithMaxLength_ExpectMaxLengthAttribute()
        {
            const int expectedMaxLength = 42;
            
            var sut = CreateSut();
            var options = new ExtendedPasswordOptions {MaxLength = expectedMaxLength};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain($"maxlength: {expectedMaxLength};");
        }

        [Theory]
        [InlineData(null)]
        [InlineData(0)]
        [InlineData(-1)]
        public void ProcessIdentityPasswordRules_WhenExtendedOptionsWithInvalidMaxLength_ExpectNoMaxLengthAttribute(int? expectedMaxLength)
        {
            var sut = CreateSut();
            var options = new ExtendedPasswordOptions {MaxLength = expectedMaxLength};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("maxlength");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(2)]
        public void ProcessIdentityPasswordRules_WhenExtendedOptionsWithMaxConsecutiveChars_ExpectMaxConsecutiveCharsAttribute(int? expectedMaxConsecutiveChars)
        {
            var sut = CreateSut();
            var options = new ExtendedPasswordOptions {MaxConsecutiveChars = expectedMaxConsecutiveChars};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().Contain($"max-consecutive: {expectedMaxConsecutiveChars};");
        }

        [Theory]
        [InlineData(null)]
        [InlineData(-1)]
        public void ProcessIdentityPasswordRules_WhenExtendedOptionsWithInvalidMaxConsecutiveChars_ExpectNoMaxConsecutiveCharsAttribute(int? expectedMaxConsecutiveChars)
        {
            var sut = CreateSut();
            var options = new ExtendedPasswordOptions {MaxConsecutiveChars = expectedMaxConsecutiveChars};
            
            sut.ProcessIdentityPasswordRules(options, testOutput);

            testOutput.Attributes["passwordrules"].Value.As<string>().Should().NotContain("max-consecutive");
        }
    }
}