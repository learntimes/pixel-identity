using System.Net.Http.Headers;
using System.Web;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;


namespace Pixel.Identity.Server.Utilities;
public class TokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor accessor;

    public TokenHandler(IHttpContextAccessor accessor) => this.accessor = accessor;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        //get the token
        var accessToken = await accessor.HttpContext.GetTokenAsync("access_token");
        //add header
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        //continue down stream request
        return await base.SendAsync(request, cancellationToken);
    }
}