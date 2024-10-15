using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.Twitter;
using Owin;
using DoAn_LapTrinhWeb.Models;

namespace DoAn_LapTrinhWeb
{
    public partial class Startup
    {
        // Removed the private DbContext field as it’s not necessary here.

        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager, and sign-in manager to use a single instance per request
            app.CreatePerOwinContext(DbContext.Create); // Pass the method reference, not the result
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed-in user
            // and to use a cookie to temporarily store information about a user logging in with a third-party login provider
            // Configure the sign-in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third-party login providers

            // Microsoft Account Authentication
            app.UseMicrosoftAccountAuthentication(new MicrosoftAccountAuthenticationOptions
            {
                ClientId = "your-client-id",
                ClientSecret = "your-client-secret"
            });

            // Twitter Authentication
            app.UseTwitterAuthentication(new TwitterAuthenticationOptions
            {
                ConsumerKey = "your-consumer-key",
                ConsumerSecret = "your-consumer-secret"
            });

            // Facebook Authentication
            app.UseFacebookAuthentication(new FacebookAuthenticationOptions
            {
                AppId = "your-app-id",
                AppSecret = "your-app-secret"
            });

            // Google Authentication
            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                ClientId = "your-client-id",
                ClientSecret = "your-client-secret"
            });
        }
    }
}
