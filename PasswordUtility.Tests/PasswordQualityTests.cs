using NUnit.Framework;
using TestStack.BDDfy;
using TestStack.BDDfy.Scanners.StepScanners.Fluent;

namespace PasswordUtility.Tests
{
    [TestFixture]
    public class PasswordQualityTests
    {
        private string testPassword;
        private uint qualityResult;

        void GivenAPassword(string password)
        {
            testPassword = password;
        }

        void WhenICalculatePasswordQuality()
        {
            qualityResult = QualityEstimation.EstimatePasswordBits(testPassword.ToCharArray());
        }

        void ThenItShouldReturnAValueGreaterThanZero()
        {
            Assert.True(qualityResult > 0);
        }
        
        [Test]
        public void ForAGivenPasswordRunningPasswordQualityShouldSucceed()
        {
            this.Given(s => s.GivenAPassword("helloWorld"), "Given a password {0}")
                .When(s => s.WhenICalculatePasswordQuality(), "When we run the CalculateQuality")
                .Then(s => s.ThenItShouldReturnAValueGreaterThanZero(), "Then we should get a value greater than 0")
                .BDDfy();
        }
    }
}
