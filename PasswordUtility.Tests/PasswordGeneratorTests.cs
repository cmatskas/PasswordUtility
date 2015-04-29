using System.Linq;
using NUnit.Framework;
using PasswordUtility.PasswordGenerator;
using TestStack.BDDfy;
using TestStack.BDDfy.Scanners.StepScanners.Fluent;

namespace PasswordUtility.Tests
{
    [TestFixture]
    public class PasswordGeneratorTests
    {
        private int passwordLength;
        private string password;

        void GivenAPasswordLength(int length)
        {
            passwordLength = length;
        }

        void WhenIGenerateANewDefaultPassword()
        {
            password = PwGenerator.Generate(passwordLength).ReadString();
        }

        void WhenWeGenerateANewPasswordWithUpperCaseCharacters()
        {
            password = PwGenerator.Generate(passwordLength, true).ReadString();
        }

        void WhenWeGenerateAPasswordWithUpperAndDigitCharacters()
        {
            password = PwGenerator.Generate(passwordLength, true, true).ReadString();
        }

        void PasswordShouldContainLowerAndUpperCaseCharacters()
        {
            var lowerCaseChars = PwCharSet.LowerCase.ToCharArray();
            var upperCaseChars = PwCharSet.UpperCase.ToCharArray();
            var passwordChars = password.ToCharArray();

            var isInvalidCharacter = false;
            foreach (var character in passwordChars)
            {
                isInvalidCharacter = !(lowerCaseChars.Contains(character) || upperCaseChars.Contains(character));
            }

            Assert.False(isInvalidCharacter);
        }

        void PasswordShouldContainUpperAndDigitCharacters()
        {
            var lowerCaseChars = PwCharSet.LowerCase.ToCharArray();
            var upperCaseChars = PwCharSet.UpperCase.ToCharArray();
            var digitChars = PwCharSet.Digits.ToCharArray();
            var passwordChars = password.ToCharArray();

            var isInvalidCharacter = false;
            foreach (var character in passwordChars)
            {
                isInvalidCharacter = !(
                    lowerCaseChars.Contains(character) 
                    || upperCaseChars.Contains(character)
                    || digitChars.Contains(character));
            }

            Assert.False(isInvalidCharacter);
        }

        void PasswordShouldOnlyContainLowerCaseCharacters()
        {
            var lowerCaseChars = PwCharSet.LowerCase.ToCharArray();
            var passwordChars = password.ToCharArray();

            var isInvalidCharacter = false;
            foreach(var character in passwordChars)
            {
                isInvalidCharacter = !lowerCaseChars.Contains(character);
            }

            Assert.False(isInvalidCharacter);
        }

        void PasswordLengthShouldBeEqualToTheDefinedLenght()
        {
            Assert.That(password.Length == passwordLength);
        }

        [Test]
        public void PasswordShouldOnlyIncludeLowerCaseCharacters()
        {
            this.Given(s => s.GivenAPasswordLength(12), "Given a password length of {0}")
                .When(s => s.WhenIGenerateANewDefaultPassword(), "When we run generate a password")
                .Then(s => s.PasswordShouldOnlyContainLowerCaseCharacters(), "Then there should only be lower case characters")
                .And(s => s.PasswordLengthShouldBeEqualToTheDefinedLenght(), "And the password length should much the defined one")
                .BDDfy();
        }

        [Test]
        public void PasswordShouldContainUpperCaseCharacters()
        {
            this.Given(s => s.GivenAPasswordLength(15), "Given a password length of {0}")
                .When(s => s.WhenWeGenerateANewPasswordWithUpperCaseCharacters(), "When we run generate a password with uppercase set to true")
                .Then(s => s.PasswordShouldContainLowerAndUpperCaseCharacters(), "Then there should be lower case and upper case characters")
                .And(s => s.PasswordLengthShouldBeEqualToTheDefinedLenght(), "And the password length should much the defined one")
                .BDDfy();
        }

        [Test]
        public void PasswordShouldContainUpperCaseAndDigitCharacters()
        {
            this.Given(s => s.GivenAPasswordLength(20), "Given a password length of {0}")
                .When(s => s.WhenWeGenerateAPasswordWithUpperAndDigitCharacters(), "When we run generate a password with uppercase and digits set to true")
                .Then(s => s.PasswordShouldContainUpperAndDigitCharacters(), "Then there should be lower and upper case and digit characters")
                .And(s => s.PasswordLengthShouldBeEqualToTheDefinedLenght(), "And the password length should much the defined one")
                .BDDfy();
        }

    }
}
