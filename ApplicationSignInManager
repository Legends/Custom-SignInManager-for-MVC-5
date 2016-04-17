 public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager) :
            base(userManager, authenticationManager)
        { }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)base.UserManager);
        }

        public override async Task<SignInStatus> PasswordSignInAsync(string userEmail, string password, bool isPersistent, bool shouldLockout)
        {
           
            SignInStatus signInStatu;
            if (this.UserManager != null)
            {
                /// changed to use email address instead of username
                Task<ApplicationUser> userAwaiter = this.UserManager.FindByEmailAsync(userEmail); 

                ApplicationUser tUser = await userAwaiter;
                if (tUser != null)
                {
                    Task<bool> cultureAwaiter1 = this.UserManager.IsLockedOutAsync(tUser.Id);
                    if (!await cultureAwaiter1)
                    {
                        Task<bool> cultureAwaiter2 = this.UserManager.CheckPasswordAsync(tUser, password);
                        if (!await cultureAwaiter2)
                        {
                            if (shouldLockout)
                            {
                                Task<IdentityResult> cultureAwaiter3 = this.UserManager.AccessFailedAsync(tUser.Id);
                                await cultureAwaiter3;
                                Task<bool> cultureAwaiter4 = this.UserManager.IsLockedOutAsync(tUser.Id);
                                if (await cultureAwaiter4)
                                {
                                    signInStatu = SignInStatus.LockedOut;
                                    return signInStatu;
                                }
                            }
                            signInStatu = SignInStatus.Failure;
                        }
                        else
                        {
                            Task<IdentityResult> cultureAwaiter5 = this.UserManager.ResetAccessFailedCountAsync(tUser.Id);
                            await cultureAwaiter5;
                            Task<SignInStatus> cultureAwaiter6 = this.SignInOrTwoFactor(tUser, isPersistent);
                            signInStatu = await cultureAwaiter6;
                        }
                    }
                    else
                    {
                        signInStatu = SignInStatus.LockedOut;
                    }
                }
                else
                {
                    signInStatu = SignInStatus.Failure;
                }
            }
            else
            {
                signInStatu = SignInStatus.Failure;
            }
            return signInStatu;
        }

        private async Task<SignInStatus> SignInOrTwoFactor(ApplicationUser user, bool isPersistent)
        {
            SignInStatus signInStatu;
            string str = Convert.ToString(user.Id);
            Task<bool> cultureAwaiter = this.UserManager.GetTwoFactorEnabledAsync(user.Id);
            if (await cultureAwaiter)
            {
                Task<IList<string>> providerAwaiter = this.UserManager.GetValidTwoFactorProvidersAsync(user.Id);
                IList<string> listProviders = await providerAwaiter;
                if (listProviders.Count > 0)
                {
                    Task<bool> cultureAwaiter2 = AuthenticationManagerExtensions.TwoFactorBrowserRememberedAsync(this.AuthenticationManager, str);
                    if (!await cultureAwaiter2)
                    {
                        ClaimsIdentity claimsIdentity = new ClaimsIdentity("TwoFactorCookie");
                        claimsIdentity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", str));
                        this.AuthenticationManager.SignIn(new ClaimsIdentity[] { claimsIdentity });
                        signInStatu = SignInStatus.RequiresVerification;
                        return signInStatu;
                    }
                }
            }
            Task cultureAwaiter3 = this.SignInAsync(user, isPersistent, false);
            await cultureAwaiter3;
            signInStatu = SignInStatus.Success;
            return signInStatu;
        }



        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
