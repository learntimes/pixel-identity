using  System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components.Authorization;

namespace Pixel.Identity.Server.Utilities;

public class CustomMessageHandler: HttpClientHandler
{
    // private readonly TokenProvider tokenProvider;
    private readonly AuthenticationStateProvider _authenticationStateProvider;

    public CustomMessageHandler(AuthenticationStateProvider tokenProvider)
    {        
        this._authenticationStateProvider = tokenProvider;
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {      
        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();        
        var accessToken = authState.User.Claims.Where(a => a.Type == "access_token").FirstOrDefault()?.Value;
        Console.WriteLine($"CustomMessageHandler Key: {accessToken}");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);;
        
        return await base.SendAsync(request, cancellationToken);
    }

}