﻿using Microsoft.AspNetCore.Components;
using MudBlazor;
using Pixel.Identity.Shared.ViewModels;
using Pixel.Identity.Server.Services;
using System.Threading.Tasks;

namespace Pixel.Identity.Server.Pages.Scopes
{
    /// <summary>
    /// Add Scope view allows user to  create a new <see cref="OpenIddict.Abstractions.OpenIddictScopeDescriptor"/>
    /// </summary>
    public partial class AddScope : ComponentBase
    {
        [Inject]
        public IDialogService Dialog { get; set; }

        [Inject]
        public IScopeService Service { get; set; }

        [Inject]
        public ISnackbar SnackBar { get; set; }

        [Inject]
        public NavigationManager Navigator { get; set; }


        ScopeViewModel scope = new ScopeViewModel();

        /// <summary>
        /// Make a post request to service endpoint to add a new scope 
        /// </summary>
        /// <returns></returns>
        async Task AddScopeAsync()
        {
            var result = await Service.AddScopeAsync(scope);
            if (result.IsSuccess)
            {                
                SnackBar.Add("Added successfully.", Severity.Success);
                Navigator.NavigateTo($"scopes/list");
                return;
            }
            SnackBar.Add(result.ToString(), Severity.Error);
        }
    }
}
