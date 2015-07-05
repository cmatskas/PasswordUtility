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

        [HttpPost]
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

    }
}