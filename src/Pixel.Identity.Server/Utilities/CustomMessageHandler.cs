using  System.Net.Http;
using System.Net.Http.Headers;

namespace Pixel.Identity.Server.Utilities;

public class CustomMessageHandler: HttpClientHandler
{
    private readonly TokenProvider tokenProvider;

    public CustomMessageHandler(TokenProvider tokenProvider)
    {        
        this.tokenProvider = tokenProvider;
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {                
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenProvider.AccessToken);;
        
        return await base.SendAsync(request, cancellationToken);
    }

}