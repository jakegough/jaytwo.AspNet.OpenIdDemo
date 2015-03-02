using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace jaytwo.AspNet.RelyingPartyDemo.Controllers
{
    public class AuthorizeAgeAttribute : AuthorizeAttribute
    {
        public int MaxAuthorizeAgeMinutes { get; private set; }

        public AuthorizeAgeAttribute(int maxAuthorizeAgeMinutes)
        {
            MaxAuthorizeAgeMinutes = maxAuthorizeAgeMinutes;
        }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            var reauth = (bool?)httpContext.Items["ReAuthenticated"];
            var result = base.AuthorizeCore(httpContext) && (reauth ?? false);
            httpContext.Items["ReAuthenticated"] = !result;
            return result;
        }
    }

    public class ProtectedController : Controller
    {
        //
        // GET: /Protected/

        public ActionResult Index()
        {
            return View();
        }

        [AuthorizeAge(1)]
        public ActionResult SuperSecure()
        {
            return View();
        }
    }
}
