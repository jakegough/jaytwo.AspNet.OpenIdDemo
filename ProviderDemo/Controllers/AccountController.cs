using jaytwo.AspNet.ProviderDemo.Code;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace jaytwo.AspNet.ProviderDemo.Controllers
{
    public class AccountController : Controller
    {
        public IFormsAuthentication FormsAuthentication { get; private set; }

        public AccountController()
            : this(new FormsAuthenticationService())
        {
        }

        public AccountController(IFormsAuthentication formsAuthentication)
        {
            FormsAuthentication = formsAuthentication;
        }

		public ActionResult SignOut()
		{
            FormsAuthentication.SignOut();
			return View();
		}

		public ActionResult LogOn()
		{
			ViewBag.ReturnUrl = Request.QueryString["ReturnUrl"];
			return View();
		}

		[HttpPost]
		public ActionResult LogOn(string username, string returnUrl)
		{
            FormsAuthentication.SignIn(username, false);
			return Redirect(returnUrl);
		}
    }
}
