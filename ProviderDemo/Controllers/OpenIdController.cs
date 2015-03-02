using DotNetOpenAuth.OpenId.Extensions.ProviderAuthenticationPolicy;
using DotNetOpenAuth.OpenId.Extensions.SimpleRegistration;
using DotNetOpenAuth.OpenId.Provider;
using DotNetOpenAuth.Messaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using DotNetOpenAuth.OpenId.Provider.Behaviors;
using jaytwo.AspNet.ProviderDemo.Code;
using System.Text.RegularExpressions;

namespace jaytwo.AspNet.ProviderDemo.Controllers
{
    public class OpenIdController : Controller
    {
		public OpenIdController()
            : this(new FormsAuthenticationService())
		{
		}

		public OpenIdController(IFormsAuthentication formsAuthentication)
		{
			this.FormsAuthentication = formsAuthentication;
		}

		public IFormsAuthentication FormsAuthentication { get; private set; }

        private bool RequestAcceptTypesIncludeXrds()
        {
            return Request.AcceptTypes != null && Request.AcceptTypes.Contains("application/xrds+xml");
        }

        public ActionResult Index()
        {
            if (RequestAcceptTypesIncludeXrds())
            {
                return Xrds(true);
            }
            else
            {
                return View();
            }
        }

        public ActionResult Discovery()
        {
            if (RequestAcceptTypesIncludeXrds())
            {
                return Xrds(true);
            }
            else
            {
                return Xrds(false);
            }
        }

        public ActionResult Xrds()
        {
            return Xrds(true);
        }

        private ActionResult Xrds(bool asProvider)
		{
            ViewBag.AsProvider = asProvider;
			return View("Xrds");
		}

		[ValidateInput(false)]
        public ActionResult Provider()
		{
            var provider = new OpenIdProvider();

            IRequest request = provider.GetRequest();
			if (request != null)
			{
				// Some requests are automatically handled by DotNetOpenAuth.  If this is one, go ahead and let it go.
				if (request.IsResponseReady)
				{
                    return provider.PrepareResponse(request).AsActionResult();
				}

				// This is apparently one that the host (the web site itself) has to respond to.
				ProviderEndpoint.PendingRequest = (IHostProcessedRequest)request;

				// If PAPE requires that the user has logged in recently, we may be required to challenge the user to log in.
				var papeRequest = ProviderEndpoint.PendingRequest.GetExtension<PolicyRequest>();
				if (papeRequest != null && papeRequest.MaximumAuthenticationAge.HasValue)
				{
					TimeSpan timeSinceLogin = DateTime.UtcNow - this.FormsAuthentication.SignedInTimestampUtc.Value;
					if (timeSinceLogin > papeRequest.MaximumAuthenticationAge.Value)
					{
						// The RP wants the user to have logged in more recently than he has.  
						// We'll have to redirect the user to a login screen.
						return this.RedirectToAction("LogOn", "Account", new { returnUrl = this.Url.Action("ProcessAuthRequest") });
					}
				}

				return this.ProcessAuthRequest();
			}
			else
			{
				// No OpenID request was recognized.  This may be a user that stumbled on the OP Endpoint.  
				return this.View();
			}
		}

		public ActionResult ProcessAuthRequest()
		{
			if (ProviderEndpoint.PendingRequest == null)
			{
				return RedirectToAction("Index");
			}

			// Try responding immediately if possible.
			ActionResult response = AutoRespondIfPossibleAsync();
			if (response != null)
			{
				return response;
			}

			// We can't respond immediately with a positive result.  But if we still have to respond immediately...
			if (ProviderEndpoint.PendingRequest.Immediate)
			{
				// We can't stop to prompt the user -- we must just return a negative response.
				return SendAssertion();
			}

            return RedirectToAction("Authenticate");
		}

        [Authorize]
        public ActionResult Authenticate()
        {
            return AutoRespondIfPossibleAsync();
        } 

		private static string GetEmailAddressForUser(string username)
		{
            // in this case, we're assuming username is email
            return username;
		}

		public ActionResult SendAssertion()
		{
			var pendingRequest = ProviderEndpoint.PendingRequest;
			var authReq = pendingRequest as IAuthenticationRequest;
			var anonReq = pendingRequest as IAnonymousRequest;
			ProviderEndpoint.PendingRequest = null; // clear session static so we don't do this again
			if (pendingRequest == null)
			{
				throw new InvalidOperationException("There's no pending authentication request!");
			}

			// Set safe defaults if somehow the user ended up (perhaps through XSRF) here before electing to send data to the RP.
			if (anonReq != null && !anonReq.IsApproved.HasValue)
			{
				anonReq.IsApproved = false;
			}

			if (authReq != null && !authReq.IsAuthenticated.HasValue)
			{
				authReq.IsAuthenticated = false;
			}

			if (authReq != null && authReq.IsAuthenticated.Value)
			{
				if (authReq.IsDirectedIdentity)
				{
                    authReq.LocalIdentifier = GetClaimedIdentifierForUser(User.Identity.Name);
				}

				if (!authReq.IsDelegatedIdentifier)
				{
					authReq.ClaimedIdentifier = authReq.LocalIdentifier;
				}
			}

			// Respond to AX/sreg extension requests only on a positive result.
			if ((authReq != null && authReq.IsAuthenticated.Value) ||
				(anonReq != null && anonReq.IsApproved.Value))
			{
				// Look for a Simple Registration request.  When the AXFetchAsSregTransform behavior is turned on
				// in the web.config file as it is in this sample, AX requests will come in as SReg requests.
				var claimsRequest = pendingRequest.GetExtension<ClaimsRequest>();
				if (claimsRequest != null)
				{
					var claimsResponse = claimsRequest.CreateResponse();

					// This simple respond to a request check may be enhanced to only respond to an individual attribute
					// request if the user consents to it explicitly, in which case this response extension creation can take
					// place in the confirmation page action rather than here.
					if (claimsRequest.Email != DemandLevel.NoRequest)
					{
						claimsResponse.Email = GetEmailAddressForUser(User.Identity.Name);
					}

					pendingRequest.AddResponseExtension(claimsResponse);
				}

				// Look for PAPE requests.
				var papeRequest = pendingRequest.GetExtension<PolicyRequest>();
				if (papeRequest != null)
				{
					var papeResponse = new PolicyResponse();
					if (papeRequest.MaximumAuthenticationAge.HasValue)
					{
						papeResponse.AuthenticationTimeUtc = DateTime.UtcNow;
					}

					pendingRequest.AddResponseExtension(papeResponse);
				}
			}

			var response = new OpenIdProvider().PrepareResponse(pendingRequest);
			return response.AsActionResult();
		}

		/// <summary>
		/// Attempts to formulate an automatic response to the RP if the user's profile allows it.
		/// </summary>
		/// <returns>The ActionResult for the caller to return, or <c>null</c> if no automatic response can be made.</returns>
		private ActionResult AutoRespondIfPossibleAsync()
		{
			// If the odds are good we can respond to this one immediately (without prompting the user)...
			if (User.Identity.IsAuthenticated)
			{
				// Is this is an identity authentication request? (as opposed to an anonymous request)...
				if (ProviderEndpoint.PendingAuthenticationRequest != null)
				{
					// If this is directed identity, or if the claimed identifier being checked is controlled by the current user...
					if (ProviderEndpoint.PendingAuthenticationRequest.IsDirectedIdentity
						|| UserControlsIdentifier(ProviderEndpoint.PendingAuthenticationRequest))
					{
						ProviderEndpoint.PendingAuthenticationRequest.IsAuthenticated = true;
						return SendAssertion();
					}
				}

				// If this is an anonymous request, we can respond to that too.
				if (ProviderEndpoint.PendingAnonymousRequest != null)
				{
					ProviderEndpoint.PendingAnonymousRequest.IsApproved = true;
					return SendAssertion();
				}
			}

			return null;
		}

		/// <summary>
		/// Checks whether the logged in user controls the OP local identifier in the given authentication request.
		/// </summary>
		/// <param name="authReq">The authentication request.</param>
		/// <returns><c>true</c> if the user controls the identifier; <c>false</c> otherwise.</returns>
		private bool UserControlsIdentifier(IAuthenticationRequest authReq)
		{
			if (authReq == null)
			{
				throw new ArgumentNullException("authReq");
			}

			if (User == null || User.Identity == null)
			{
				return false;
			}

			Uri userLocalIdentifier = GetClaimedIdentifierForUser(User.Identity.Name);
			return authReq.LocalIdentifier == userLocalIdentifier ||
				authReq.LocalIdentifier == PpidGeneration.PpidIdentifierProvider.GetIdentifier(userLocalIdentifier, authReq.Realm);
		}

        public ActionResult Identity(string id)
        {
            Uri normalized = GetClaimedIdentifierForUser(id);
            if (Request.Url != normalized)
            {
                return Redirect(normalized.AbsoluteUri);
            }

            if (RequestAcceptTypesIncludeXrds())
            {
                return Xrds(false);
            }

            this.ViewData["username"] = id;
            return View();
        }

        private const string claimedIdentifierPath = "OpenId/Identity/";

        internal Uri ClaimedIdentifierBaseUri
        {
            get { return GetAppPathRootedUri(claimedIdentifierPath); }
        }

        internal Uri GetClaimedIdentifierForUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException("username");
            }

            return new Uri(ClaimedIdentifierBaseUri, username.ToLowerInvariant());
        }

        internal static string GetUserFromClaimedIdentifier(Uri claimedIdentifier)
        {
            Regex regex = new Regex("/" + claimedIdentifierPath + @"([^/\?]+)");
            Match m = regex.Match(claimedIdentifier.AbsoluteUri);
            if (!m.Success)
            {
                throw new ArgumentException();
            }

            return m.Groups[1].Value;
        }

        internal Uri GetNormalizedClaimedIdentifier(Uri uri)
        {
            return GetClaimedIdentifierForUser(GetUserFromClaimedIdentifier(uri));
        }

        internal Uri GetAppPathRootedUri(string value)
        {
            string appPath = Request.ApplicationPath.ToLowerInvariant();
            if (!appPath.EndsWith("/"))
            {
                appPath += "/";
            }

            return new Uri(Request.Url, appPath + value);
        }
    }
}
