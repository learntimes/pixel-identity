using Microsoft.AspNetCore.Components.Authorization;
using System.Linq;
using System.Threading.Tasks;

namespace Pixel.Identity.Server.Utilities;

public interface ICustomAuthenticationService
{
    bool IsAuthenticated { get; }
    
    string AccessToken { get;}

    Task Setup();

}
public class CustomAuthenticationService : ICustomAuthenticationService
{
    private readonly AuthenticationStateProvider _authenticationStateProvider;

    public CustomAuthenticationService(AuthenticationStateProvider authenticationStateProvider)
    {
        _authenticationStateProvider = authenticationStateProvider;
        Setup().GetAwaiter().GetResult();
    }

    public bool IsAuthenticated { get; private set; } = false;
    public string AccessToken { get; private set;} = "";

    public async Task Setup()
    {
        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
        IsAuthenticated = false;
        if (authState.User.Identity.IsAuthenticated)
        {
            // Here we grab some details we need from the AuthState User
            // var inRole = authState.User.IsInRole("Admin");
            // Here is where we cache the AccessToke for later use.
            AccessToken = authState.User.Claims.Where(a => a.Type == "access_token").FirstOrDefault()?.Value;
            var name = authState.User.Claims.Where(a => a.Type == "name").FirstOrDefault()?.Value;
            // var preferredUsername = authState.User.Claims.Where(a => a.Type == "preferred_username").FirstOrDefault()?.Value;

           IsAuthenticated = true;
        }
    }

   
}