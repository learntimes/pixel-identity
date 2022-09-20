using Microsoft.AspNetCore.WebUtilities;
using Pixel.Identity.Shared.Models;
using Pixel.Identity.Shared.Request;
using Pixel.Identity.Shared.Responses;
using Pixel.Identity.Shared.ViewModels;
using Pixel.Identity.Server.Utilities;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using System.Text;
using Newtonsoft.Json;

namespace Pixel.Identity.Server.Services
{
    /// <summary>
    /// Service contract for consuming scopes api to manage sccopes
    /// </summary>
    public interface IScopeService
    {
        /// <summary>
        /// Get all the available scopes based on request
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        Task<PagedList<ScopeViewModel>> GetScopesAsync(GetScopesRequest request);

        /// <summary>
        /// Get scope details given scope id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        Task<ScopeViewModel> GetByIdAsync(string id);

        /// <summary>
        /// Add a new scope
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        Task<OperationResult> AddScopeAsync(ScopeViewModel scope);
       
        /// <summary>
        /// Update details of an existing scope
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        Task<OperationResult> UpdateScopeAsync(ScopeViewModel scope);


        /// <summary>
        /// Update details of an existing scope
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        Task<OperationResult> DeleteScopeAsync(ScopeViewModel scope);
    }

    public class ScopeService : IScopeService
    {
        private readonly HttpClient httpClient;
        private readonly TokenProvider tokenProvider;

        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="httpClient"></param>
        // public ScopeService(HttpClient httpClient)
        // {
        //     this.httpClient = httpClient;            
        // }

        public ScopeService(HttpClient httpClient, TokenProvider tokenProvider)
        { 
            this.httpClient = httpClient;             
            this.tokenProvider = tokenProvider;           
        }
        /// <inheritdoc/>
        public async Task<PagedList<ScopeViewModel>> GetScopesAsync(GetScopesRequest request)
        {
            // var configuration = await httpClient.GetDiscoveryDocumentAsync("https://localhost:7109/pauth");
            // if (configuration.IsError)
            // {
            //     throw new Exception($"An error occurred while retrieving the configuration document: {configuration.Error}");
            // }

            // var response = await httpClient.RequestPasswordTokenAsync(new PasswordTokenRequest
            // {
            //     Address = configuration.TokenEndpoint,
            //     UserName = "admin@pixel.com",
            //     Password = "Admi9@pixel",
            //     Scope = OidcConstants.StandardScopes.OfflineAccess
            // });

            // if (response.IsError)
            // {
            //     throw new Exception($"An error occurred while retrieving an access token: {response.Error}");
            // }

            // // return (response.AccessToken, response.RefreshToken);
            // Console.WriteLine(response.AccessToken);

            var token = tokenProvider.AccessToken;

            Console.WriteLine("scopserverices key : " + token);

            var queryStringParam = new Dictionary<string, string?>
            {
                ["currentPage"] = request.CurrentPage.ToString(),
                ["pageSize"] = request.PageSize.ToString()
            };
            if (!string.IsNullOrEmpty(request.ScopesFilter))
            {
                queryStringParam.Add("scopesFilter", request.ScopesFilter);
            }  

           Console.WriteLine("地址");
           Console.WriteLine(QueryHelpers.AddQueryString($"https://localhost:7109/api/Scopes/GetAll", queryStringParam));      

            var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(QueryHelpers.AddQueryString($"https://localhost:7109/api/Scopes/GetAll", queryStringParam)),
                Headers = {
                    { HttpRequestHeader.Authorization.ToString(), "Bearer "+token },
                    { HttpRequestHeader.Accept.ToString(), "application/json" },
                    { HttpRequestHeader.AcceptCharset.ToString(), "utf-8"}                    
                }              
            };    
            HttpResponseMessage httpResponse = await httpClient.SendAsync(httpRequestMessage);

            string content = await httpResponse.Content.ReadAsStringAsync();

            Console.WriteLine(content);

            return JsonConvert.DeserializeObject<PagedList<ScopeViewModel>>(content);

           
            // return await httpResponse.Content.ReadFromJsonAsync<PagedList<ScopeViewModel>>();

            // return await this.httpClient.GetFromJsonAsync<PagedList<ScopeViewModel>>(QueryHelpers.AddQueryString("Scopes/GetAll", queryStringParam));
           
            
        }

        /// <inheritdoc/>
        public async Task<ScopeViewModel> GetByIdAsync(string id)
        {
            return await httpClient.GetFromJsonAsync<ScopeViewModel>($"api/scopes/id/{id}");          
        }

        /// <inheritdoc/>
        public async Task<OperationResult> AddScopeAsync(ScopeViewModel scope)
        {
            var result = await httpClient.PostAsJsonAsync<ScopeViewModel>("api/scopes", scope);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> UpdateScopeAsync(ScopeViewModel scope)
        {
            var result = await httpClient.PutAsJsonAsync<ScopeViewModel>("api/scopes", scope);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> DeleteScopeAsync(ScopeViewModel scope)
        {
            var result = await httpClient.DeleteAsync($"api/scopes/{scope.Id}");
            return await OperationResult.FromResponseAsync(result);
        }
    }
}
