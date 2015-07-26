using System.Web.Optimization;

namespace PasswordUtility.Web
{
    public class BundleConfig
    {
        // For more information on bundling, visit http://go.microsoft.com/fwlink/?LinkId=301862
        public static void RegisterBundles(BundleCollection bundles)
        {
            bundles.Add(new ScriptBundle("~/bundles/javascript").Include(
                        "~/Scripts/jquery.min.js",
                        "~/Scripts/jquery.dropotron.min.js",
                        "~/Scripts/skel.min.js",
                        "~/Scripts/skel-viewport.min.js",
                        "~/Scripts/util.js",
                        "~/Scripts/main.js",
                        "~/Scripts/bootstrap.js",
                        "~/Scripts/site.js"));

            bundles.Add(new ScriptBundle("~/bundles/jqueryval").Include(
                        "~/Scripts/jquery.validate*"));

            // Use the development version of Modernizr to develop with and learn from. Then, when you're
            // ready for production, use the build tool at http://modernizr.com to pick only the tests you need.
            bundles.Add(new ScriptBundle("~/bundles/modernizr").Include(
                        "~/Scripts/modernizr-*"));
            
            bundles.Add(new StyleBundle("~/Content/css").Include(
                      "~/Content/bootstrap.css",
                      "~/Content/main.css",
                      "~/font-awesome.min.css"));
        }
    }
}
