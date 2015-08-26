using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Http;
using System.Web.Http.Results;
using PasswordUtility.Web.Models;
using System.Web.Mvc;

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
        public ActionResult Index(PasswordModel model)
        {
            if (string.IsNullOrEmpty(model.PasswordRequest))
            {
                ViewBag.Error = "Cannot validate an empty password";
                return Index(model);
            }

            model.PasswordResult = QualityEstimation.EstimatePasswordBits(model.PasswordRequest.ToCharArray()).ToString();
            return Index(model);
        }

        [System.Web.Mvc.HttpPost]
        public JsonResult Validate(string password)
        {
            var result = QualityEstimation.EstimatePasswordBits(password.ToCharArray()).ToString();
            return Json(result);
        }

    }
}