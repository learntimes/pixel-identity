using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Pixel.Identity.Core.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    [IdentityDefaultUI(typeof(ExternalLoginModel<,>))]
    public class ExternalLoginModel : PageModel
    {
        [BindProperty]
        public InputModel Input { get; set; }

        public string ProviderDisplayName { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }
        }

        public virtual IActionResult OnGet() => throw new NotImplementedException();

        public virtual IActionResult OnPost(string provider, string returnUrl = null) => throw new NotImplementedException();

        public virtual Task<IActionResult> OnGetCallbackAsync(string returnUrl = null, string remoteError = null) => throw new NotImplementedException();

        public virtual Task<IActionResult> OnPostConfirmationAsync(string returnUrl = null) => throw new NotImplementedException();
    }

    public class ExternalLoginModel<TUser, TKey> : ExternalLoginModel
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly SignInManager<TUser> signInManager;
        private readonly UserManager<TUser> userManager;
        private readonly IUserStore<TUser> userStore;
        private readonly IUserEmailStore<TUser> emailStore;
        private readonly IEmailSender emailSender;
        private readonly ILogger<ExternalLoginModel> logger;

        public ExternalLoginModel(
            SignInManager<TUser> signInManager,
            UserManager<TUser> userManager,
            IUserStore<TUser> userStore,
            ILogger<ExternalLoginModel> logger,
            IEmailSender emailSender)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.userStore = userStore;
            emailStore = GetEmailStore();
            this.logger = logger;
            this.emailSender = emailSender;
        }

        public override IActionResult OnGet() => RedirectToPage("./Login");

        public override IActionResult OnPost(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        public override async Task<IActionResult> OnGetCallbackAsync(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }
            // var info = await signInManager.GetExternalLoginInfoAsync();            
            var info = await Custom_GetExternalLoginInfoAsync();
            if (info == null)
            {
                ErrorMessage = "Error loading external login information.1";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                Console.WriteLine("ExternalSignIn Success...... ");
                logger.LogInformation("User logged in with {LoginProvider} provider.", info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                Console.WriteLine("ExternalSignIn Fail...... ");
                // If the user does not have an account, then ask the user to create an account.
                ReturnUrl = returnUrl;
                ProviderDisplayName = info.ProviderDisplayName;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    Input = new InputModel
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
                    };
                }
                return Page();
            }
        }

        private async Task<ExternalLoginInfo> Custom_GetExternalLoginInfoAsync()
        {

            var rt = await HttpContext.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);

            #region 用于测试

            if (rt != null)
            {
                if (rt.Ticket != null)
                {
                    Console.WriteLine("===================显示Ticket中的数据 : ===================");
                    Console.WriteLine("Start Output Items Of TicketProperties :");
                    foreach (var item in rt.Ticket.Properties.Items)
                    {
                        Console.WriteLine(item.Key + " : " + item.Value);
                    }
                }

                if (rt.Properties.Items != null)
                {
                    Console.WriteLine("===================显示Properties中的数据 : ===================");
                    Console.WriteLine("Start Output Items Of ResultProperties :");
                    foreach (var item in rt.Properties.Items)
                    {
                        Console.WriteLine(item.Key + " : " + item.Value);

                    }
                }
                if (rt.Principal != null)
                {
                    Console.WriteLine("===================显示Principal中的数据 : ===================");
                    Console.WriteLine("Start Output Identities Claims Of ResultProperties :");
                    foreach (var item in rt.Principal.Identities)
                    {
                        Console.WriteLine(item.Name + " : ");
                        foreach (var ci in item.Claims)
                        {
                            Console.WriteLine(ci.Value);
                        }
                    }
                    Console.WriteLine("Start Output Each Claim Of ResultProperties :");
                    foreach (var item in rt.Principal.Claims)
                    {
                        Console.WriteLine(item.Type + " : " + item.Value);
                    }
                }
            }

            Console.WriteLine("===================显示User中的数据 : ===================");
            Console.WriteLine("Start Output Each Claim Of User :");
            foreach (var item in User.Claims)
            {
                Console.WriteLine(item.Type + " : " + item.Value);
            }

            Console.WriteLine("User.Identity.Name :" + User.Identity.Name);

            #endregion

            // var providerKey = rt.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            // string providerKey = rt.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value.ToString();
            //上面providerKey测试无效    
            string providerKey = rt.Principal.Claims.Where(c => c.Type == "sub").FirstOrDefault().Value.ToString();
            var provider = rt.Properties.Items["LoginProvider"] as string;
            Console.WriteLine("provider : " + provider);
            Console.WriteLine("providerKey : " + providerKey);

            if (providerKey == null || provider == null)
            {
                return null;
            }
            var providerDisplayName = (await signInManager.GetExternalAuthenticationSchemesAsync()).FirstOrDefault(p => p.Name == provider)?.DisplayName
                                        ?? provider;
            Console.WriteLine("providerDisplayName : " + providerDisplayName);

            var info = new ExternalLoginInfo(rt.Principal, provider, providerKey, providerDisplayName)
            {
                AuthenticationTokens = rt.Properties?.GetTokens(),
                AuthenticationProperties = rt.Properties
            };

            return info;
        }

        public override async Task<IActionResult> OnPostConfirmationAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            // Get the information about the user from the external login provider
            // var info = await signInManager.GetExternalLoginInfoAsync();
            var info = await Custom_GetExternalLoginInfoAsync();
            if (info == null)
            {
                ErrorMessage = "Error loading external login information during confirmation.";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }

            if (ModelState.IsValid)
            {
                var user = CreateUser();

                await userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

                var result = await userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);

                        var userId = await userManager.GetUserIdAsync(user);
                        var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                        var callbackUrl = Url.Page(
                            "/Account/ConfirmEmail",
                            pageHandler: null,
                            values: new { area = "Identity", userId = userId, code = code },
                            protocol: Request.Scheme);

                        await emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                        // If account confirmation is required, we need to show the link if we don't have a real email sender
                        if (userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            return RedirectToPage("./RegisterConfirmation", new { Email = Input.Email });
                        }

                        await signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                        return LocalRedirect(returnUrl);
                    }
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            ProviderDisplayName = info.ProviderDisplayName;
            ReturnUrl = returnUrl;
            return Page();
        }

        private TUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<TUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(TUser)}'. " +
                    $"Ensure that '{nameof(TUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the external login page in /Areas/Identity/Pages/Account/ExternalLogin.cshtml");
            }
        }

        private IUserEmailStore<TUser> GetEmailStore()
        {
            if (!userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<TUser>)userStore;
        }
    }
}

