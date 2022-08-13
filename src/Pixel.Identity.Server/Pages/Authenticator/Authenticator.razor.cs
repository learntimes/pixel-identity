﻿using Microsoft.AspNetCore.Components;
using Pixel.Identity.Server.Services;
using System.Threading.Tasks;

namespace Pixel.Identity.Server.Pages.Authenticator
{
    /// <summary>
    /// Self managment page for user authenticator for 2FA
    /// </summary>
    public partial class Authenticator : ComponentBase
    {
        [Inject]
        public IAuthenticatorService Service { get; set; }

        [Inject]
        public NavigationManager Navigator { get; set; }

        protected override async Task OnInitializedAsync()
        {
            if(!await Service.CheckIsAuthenticatorEnabledAsync())
            {
                Navigator.NavigateTo("account/authenticator/enable");
            }

            await base.OnInitializedAsync();
        }
    }
}
