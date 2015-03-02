using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Extensions.SimpleRegistration;
using DotNetOpenAuth.OpenId.RelyingParty;
using DotNetOpenAuth.Messaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.OpenId.Extensions.AttributeExchange;
using System.Collections.Specialized;
using DotNetOpenAuth.OpenId.Extensions.ProviderAuthenticationPolicy;

namespace jaytwo.AspNet.RelyingPartyDemo.Controllers
{
    public class LoginController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignIn(string username, string returnUrl)
        {
            FormsAuthentication.SetAuthCookie(username, false);
            return Redirect(returnUrl);
        }

        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            return Redirect("~/");
        }

        public ActionResult OpenId()
        {
            //var discoveryUrl = "https://www.google.com/accounts/o8/id";
            var discoveryUrl = "http://localhost.jaytwo.com:14505/OpenId/Discovery";
            var realm = new Uri(Request.Url, Url.Content("~/"));
            
            var reutrnUriBase = new Uri(Request.Url, Url.Action("OpenIdReturn"));
            var reutrnUriBuilder = new UriBuilder(reutrnUriBase);
            reutrnUriBuilder.Query = Request.QueryString.ToString();
            var reutrnUri = reutrnUriBuilder.Uri;

            var request = new OpenIdRelyingParty().CreateRequest(discoveryUrl, realm, reutrnUri);
            request.Mode = AuthenticationRequestMode.Setup;
            request.AddExtension(new ClaimsRequest { Email = DemandLevel.Require });
            //request.AddExtension(new PolicyRequest { MaximumAuthenticationAge = TimeSpan.Zero });

            //var extension = new FetchRequest();
            //extension.Attributes.AddRequired("http://login.jaytwo.com/OpenId/Attributes/SessionId");
            //extension.Attributes.AddRequired("http://login.jaytwo.com/OpenId/Attributes/Roles");
            //request.AddExtension(extension);

            var appReturnUrl = Request.QueryString["ReturnUrl"];
            if (string.IsNullOrEmpty(appReturnUrl))
            {
                appReturnUrl = Url.Content("~/");
            }

            request.AddCallbackArguments("appReturnUrl", appReturnUrl);

            request.AddCallbackArguments("state", "hello world");

            return request.RedirectingResponse.AsActionResult();
        }

        public ActionResult OpenIdReturn()
        {
			var relyingParty = new OpenIdRelyingParty();
			var response = relyingParty.GetResponse();

            if (response != null)
            {
                switch (response.Status)
                {
                    case AuthenticationStatus.Authenticated:
                        var state = response.GetCallbackArgument("state");
                        var appReturnUrl = response.GetCallbackArgument("appReturnUrl");

                        var fetch = response.GetExtension<FetchResponse>();
                        string email;
                        string fullName;
                        string nickName;
                        if (fetch != null)
                        {
                            email = fetch.GetAttributeValue(WellKnownAttributes.Contact.Email);
                            fullName = fetch.GetAttributeValue(WellKnownAttributes.Name.FullName);
                            if (string.IsNullOrEmpty(fullName))
                            {
                                fullName = fetch.GetAttributeValue(WellKnownAttributes.Name.First) +
                                " " + fetch.GetAttributeValue(WellKnownAttributes.Name.Last);
                            }
                            nickName = fetch.GetAttributeValue(WellKnownAttributes.Name.Alias);
                        }
                        else
                        {
                            var claimsResponse = response.GetExtension<ClaimsResponse>();
                            email = claimsResponse.Email;
                            fullName = claimsResponse.FullName;
                            nickName = claimsResponse.Nickname;
                        }

                        return SignIn(email, appReturnUrl);
                    case AuthenticationStatus.Canceled:
                        ModelState.AddModelError("loginIdentifier", "Login was cancelled at the provider");
                        break;
                    case AuthenticationStatus.Failed:
                        ModelState.AddModelError("loginIdentifier", "Login failed using the provided OpenId identifier : " + response.Exception.Message);
                        break;
                }
            }

            return View();
        } 
    }
}
