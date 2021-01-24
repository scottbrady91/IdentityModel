using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;
using ScottBrady.IdentityModel.AspNetCore.Identity;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.AspNetCore.Identity
{
    public class ExtendedPasswordValidatorTests
    {
        private ExtendedPasswordValidator<IdentityUser> CreateSut() => new ExtendedPasswordValidator<IdentityUser>();

        private Mock<ExtendedPasswordValidator<IdentityUser>> CreateMockedSut()
        {
            var sut = new Mock<ExtendedPasswordValidator<IdentityUser>>() {CallBase = true};
            sut.Setup(x => x.HasConsecutiveCharacters(It.IsAny<string>(), It.IsAny<int>())).Returns(false);
            return sut;
        }

        [Fact]
        public async Task ValidateAsync_WhenUserManagerIsNull_ExpectArgumentNullException()
        {
            var sut = CreateMockedSut();
            await Assert.ThrowsAsync<ArgumentNullException>(() => sut.Object.ValidateAsync(null, new IdentityUser(), "password"));
        }

        [Fact]
        public async Task ValidateAsync_WhenPasswordIsNull_ExpectArgumentNullException()
        {
            var sut = CreateMockedSut();
            await Assert.ThrowsAsync<ArgumentNullException>(() => sut.Object.ValidateAsync(CreateMockUserManager().Object, new IdentityUser(), null));
        }

        [Fact]
        public async Task ValidateAsync_WhenPasswordOptionsAreNotExtendedPasswordOptions_ExpectSuccess()
        {
            var options = new PasswordOptions();
            
            var sut = CreateMockedSut();
            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), "123");

            result.Succeeded.Should().BeTrue();
        }

        [Fact]
        public async Task ValidateAsync_WhenPasswordOptionsAreExtendedPasswordOptionsButNotSet_ExpectSuccess()
        {
            var options = new ExtendedPasswordOptions();
            
            var sut = CreateMockedSut();
            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), "123");

            result.Succeeded.Should().BeTrue();
        }

        [Theory]
        [InlineData(1, "123")]
        [InlineData(3, "1234")]
        public async Task ValidateAsync_WhenExtendedPasswordOptionsAndPasswordIsTooLong_ExpectError(int maxLength, string password)
        {
            var options = new ExtendedPasswordOptions{MaxLength = maxLength};
            
            var sut = CreateMockedSut();
            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), password);

            result.Succeeded.Should().BeFalse();
            result.Errors.Should().Contain(x => x.Code == "PasswordTooLong" && x.Description.Contains(options.MaxLength.ToString()));
        }

        [Theory]
        [InlineData(-1, "123")]
        [InlineData(0, "123")]
        [InlineData(4, "123")]
        [InlineData(3, "123")]
        public async Task ValidateAsync_WhenExtendedPasswordOptionsAndPasswordIsNotTooLong_ExpectSuccess(int maxLength, string password)
        {
            var options = new ExtendedPasswordOptions{MaxLength = maxLength};
            
            var sut = CreateMockedSut();
            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), password);

            result.Succeeded.Should().BeTrue();
        }

        [Theory]
        [InlineData(-1, "123")]
        [InlineData(0, "123")]
        [InlineData(3, "123")]
        public async Task ValidateAsync_WhenExtendedPasswordOptionsAndMaxConsecutiveCharactersValid_ExpectSuccess(int maxConsecutive, string password)
        {
            var options = new ExtendedPasswordOptions {MaxConsecutiveChars = maxConsecutive};
            
            var sut = CreateMockedSut();
            sut.Setup(x => x.HasConsecutiveCharacters(password, maxConsecutive)).Returns(false);

            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), password);

            result.Succeeded.Should().BeTrue();
        }

        [Fact]
        public async Task ValidateAsync_WhenExtendedPasswordOptionsAndTooManyMaxConsecutiveCharacters_ExpectError()
        {
            const string password = "Password123!";
            var options = new ExtendedPasswordOptions {MaxConsecutiveChars = 2};
            
            var sut = CreateMockedSut();
            sut.Setup(x => x.HasConsecutiveCharacters(password, options.MaxConsecutiveChars.Value)).Returns(true);

            var result = await sut.Object.ValidateAsync(CreateMockUserManager(options).Object, new IdentityUser(), password);

            result.Succeeded.Should().BeFalse();
            result.Errors.Should().Contain(x => x.Code == "TooManyConsecutiveCharacters" && x.Description.Contains(options.MaxConsecutiveChars.ToString()));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void HasConsecutiveCharacters_WhenPasswordIsNullOrWhitespace_ExpectArgumentNullException(string password)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.HasConsecutiveCharacters(password, 42));
        }
        
        [Theory]
        [InlineData(0, "qwerty")]
        [InlineData(1, "qwerty")]
        [InlineData(2, "qwerty")]
        [InlineData(2, "qqwerty")]
        [InlineData(1, "qwertyuiopasdfghjklzxcvbnm")]
        public void HasConsecutiveCharacters_WhenNoConsecutiveCharacters_ExpectFalse(int max, string password)
        {
            var sut = CreateSut();
            var hasConsecutiveCharacters = sut.HasConsecutiveCharacters(password, max);

            hasConsecutiveCharacters.Should().BeFalse();
        }
        
        [Fact]
        public void HasConsecutiveCharacters_WhenConsecutiveCharactersButUnderLimit_ExpectFalse()
        {
            const int maxConsecutiveCharacters = 2;
            const string password = "qqwweerrttyy";

            var sut = CreateSut();
            var hasConsecutiveCharacters = sut.HasConsecutiveCharacters(password, maxConsecutiveCharacters);

            hasConsecutiveCharacters.Should().BeFalse();
        }
        
        [Fact]
        public void HasConsecutiveCharacters_WhenConsecutiveCharactersButDifferentCasing_ExpectFalse()
        {
            const int maxConsecutiveCharacters = 2;
            const string password = "QqQwerty";

            var sut = CreateSut();
            var hasConsecutiveCharacters = sut.HasConsecutiveCharacters(password, maxConsecutiveCharacters);

            hasConsecutiveCharacters.Should().BeFalse();
        }
        
        [Theory]
        [InlineData(1, "qqqwertyy")]
        [InlineData(2, "qqqwertyy")]
        [InlineData(2, "qwertyyy")]
        [InlineData(3, "qwertyyyy")]
        public void HasConsecutiveCharacters_WhenConsecutiveCharactersAndOverLimit_ExpectTrue(int max, string password)
        {
            var sut = CreateSut();
            var hasConsecutiveCharacters = sut.HasConsecutiveCharacters(password, max);

            hasConsecutiveCharacters.Should().BeTrue();
        }

        private static Mock<UserManager<IdentityUser>> CreateMockUserManager(PasswordOptions options = null)
            => new Mock<UserManager<IdentityUser>>(new Mock<IUserStore<IdentityUser>>().Object,
                new OptionsWrapper<IdentityOptions>(new IdentityOptions {Password = options ?? new PasswordOptions()}), null, null, null, null, null, null, null);
    }
}