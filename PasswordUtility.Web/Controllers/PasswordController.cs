using System;
using System.Web.Http;
using System.Web.Http.Results;
using PasswordUtility.PasswordGenerator;

namespace PasswordUtility.Web.Controllers
{
    [RoutePrefix("api/password")]
    public class PasswordController : ApiController
    {
        [Route("validate")]
        [HttpPost]
        public IHttpActionResult Validate(string password)
        {
            var validationResult = 0;
            try
            {
                validationResult = (int)QualityEstimation.EstimatePasswordBits(password.ToCharArray());
            }
            catch (Exception e)
            {
                return InternalServerError(e);
            }

            return Ok(validationResult);
        }

        [Route("generate")]
        public IHttpActionResult Generate(int length, bool upperCase = false, bool digits = true, bool specialCharacters = false)
        {
            string password;
            try
            {
                password = PwGenerator.Generate(length, upperCase, digits, specialCharacters).ReadString();
            }
            catch (Exception e)
            {
                return InternalServerError(e);
            }

            return Ok(password);
        }

    }
}
