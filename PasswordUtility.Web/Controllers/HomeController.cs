using System.Net;
using PasswordUtility.Web.Models;
using System.Web.Mvc;
using PasswordUtility.PasswordGenerator;

namespace PasswordUtility.Web.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            return View(new PasswordModel());
        }

        [System.Web.Mvc.HttpPost]
        public JsonResult Validate(string password)
        {
            var result = QualityEstimation.EstimatePasswordBits(password.ToCharArray()).ToString();
            return Json(result);
        }

        [System.Web.Mvc.HttpPost]
        public JsonResult Generate(bool uppercase, bool numeric, bool specialchars, int length)
        {
            var result = PwGenerator.Generate(length, uppercase, numeric, specialchars).ReadString();
            return Json(result);
        }

    }
}