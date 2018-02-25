// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer4.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    public class AccountController : Controller
    {
        private readonly TestUserStore _users;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
		private readonly UserManager<IdentityUser> _userManager;
		private readonly AccountService _account;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
			IHttpContextAccessor httpContextAccessor,
			IAuthenticationSchemeProvider schemeProvider,
			IEventService events,
			UserManager<IdentityUser> userManager)
        {
			_schemeProvider = schemeProvider;
			_userManager = userManager;
			_interaction = interaction;
            _events = events;
			_clientStore = clientStore;
			_account = new AccountService(interaction, httpContextAccessor, schemeProvider, clientStore);
		}

        /// <summary>
        /// Show login page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return await ExternalLogin(vm.ExternalLoginScheme, returnUrl);
            }

            return View(vm);
        }

		/// <summary>
		/// Handle postback from username/password login
		/// </summary>
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Login(LoginInputModel model, string button)
		{
			if (button != "login")
			{
				var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
				if (context != null)
				{
					await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);
					return Redirect(model.ReturnUrl);
				}
				else
				{
					return Redirect("~/");
				}
			}

			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByNameAsync(model.Username);

				if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
				{
					await _events.RaiseAsync(
						new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

					AuthenticationProperties props = null;
					if (AccountOptions.AllowRememberLogin && model.RememberLogin)
					{
						props = new AuthenticationProperties
						{
							IsPersistent = true,
							ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
						};
					};

					await HttpContext.SignInAsync(user.Id, user.UserName, props);

					if (_interaction.IsValidReturnUrl(model.ReturnUrl)
							|| Url.IsLocalUrl(model.ReturnUrl))
					{
						return Redirect(model.ReturnUrl);
					}

					return Redirect("~/");
				}

				await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
				ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
			}

			var vm = await _account.BuildLoginViewModelAsync(model);
			return View(vm);
		}

		/// <summary>
		/// initiate roundtrip to external authentication provider
		/// </summary>
		[HttpGet]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
        {
			var props = new AuthenticationProperties()
			{
				RedirectUri = Url.Action("ExternalLoginCallback"),
				Items =
				{
					{ "returnUrl", returnUrl }
				}
			};

			// windows authentication needs special handling
			// since they don't support the redirect uri, 
			// so this URL is re-triggered when we call challenge
			if (AccountOptions.WindowsAuthenticationSchemeName == provider)
			{
				// see if windows auth has already been requested and succeeded
				var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
				if (result?.Principal is WindowsPrincipal wp)
				{
					props.Items.Add("scheme", AccountOptions.WindowsAuthenticationSchemeName);

					var id = new ClaimsIdentity(provider);
					id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
					id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

					// add the groups as claims -- be careful if the number of groups is too large
					if (AccountOptions.IncludeWindowsGroups)
					{
						var wi = wp.Identity as WindowsIdentity;
						var groups = wi.Groups.Translate(typeof(NTAccount));
						var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
						id.AddClaims(roles);
					}

					await HttpContext.SignInAsync(
						IdentityConstants.ExternalScheme,
						new ClaimsPrincipal(id),
						props);
					return Redirect(props.RedirectUri);
				}
				else
				{
					// challenge/trigger windows auth
					return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
				}
			}
			else
			{
				// start challenge and roundtrip the return URL
				props.Items.Add("scheme", provider);
				return Challenge(props, provider);
			}
		}

		/// <summary>
		/// Post processing of external authentication
		/// </summary>
		[HttpGet]
		public async Task<IActionResult> ExternalLoginCallback()
		{
			var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
			if (result?.Succeeded != true)
			{
				throw new Exception("External authentication error");
			}

			var externalUser = result.Principal;
			var claims = externalUser.Claims.ToList();

			var userIdClaim = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Subject);
			if (userIdClaim == null)
			{
				userIdClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
			}
			if (userIdClaim == null)
			{
				throw new Exception("Unknown userid");
			}

			claims.Remove(userIdClaim);
			var provider = result.Properties.Items["scheme"];
			var userId = userIdClaim.Value;

			var user = await _userManager.FindByLoginAsync(provider, userId);
			if (user == null)
			{
                var userName = claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
                if (userName != null)
                    user = new IdentityUser { UserName = userName.Value };
                else
                    user = new IdentityUser { UserName = Guid.NewGuid().ToString() };

                await _userManager.CreateAsync(user);
				await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, userId, provider));
			}

			var additionalClaims = new List<Claim>();

			var sid = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
			if (sid != null)
			{
				additionalClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
			}

			AuthenticationProperties props = null;
			var id_token = result.Properties.GetTokenValue("id_token");
			if (id_token != null)
			{
				props = new AuthenticationProperties();
				props.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
			}

			await _events.RaiseAsync(new UserLoginSuccessEvent(provider, userId, user.Id, user.UserName));
			await HttpContext.SignInAsync(
				user.Id, user.UserName, provider, props, additionalClaims.ToArray());

			await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

			var returnUrl = result.Properties.Items["returnUrl"];
			if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}

			return Redirect("~/");
		}

		/// <summary>
		/// Show logout page
		/// </summary>
		[HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, tresting windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("ExternalLoginCallback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (AccountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }

        private (TestUser user, string provider, string providerUserId, IEnumerable<Claim> claims) FindUserFromExternalProvider(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = _users.FindByExternalProvider(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        private TestUser AutoProvisionUser(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            var user = _users.AutoProvisionUser(provider, providerUserId, claims.ToList());
            return user;
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }
    }
}