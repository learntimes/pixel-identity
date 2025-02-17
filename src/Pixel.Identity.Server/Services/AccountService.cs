﻿using Pixel.Identity.Shared.Models;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Pixel.Identity.Server.Utilities;
using System.Xml;
using System.Xml.Serialization;
using System.IO;

namespace Pixel.Identity.Server.Services
{
    /// <summary>
    /// Service contract for consuming account api to manage user account
    /// </summary>
    public interface IAccountService
    {
        /// <summary>
        /// Get whether user has account has a password.       
        /// </summary>
        /// <returns></returns>
        Task<bool> GetHasPasswordAsync();

        /// <summary>
        /// Send the password reset link to user registered email
        /// </summary>
        /// <returns></returns>
        Task<OperationResult> SendPasswordResetLinkAsync(ForgotPasswordModel model);

        /// <summary>
        /// Resend the email confirmation link to user registered email
        /// </summary>
        /// <param name="userName">Name of the user</param>
        /// <returns></returns>
        Task<OperationResult> ResendEmailConfirmationAsync(ResendEmailConfirmationModel model);

        /// <summary>
        /// Change user password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        Task<OperationResult> ChangePasswordAsync(ChangePasswordModel model);

        /// <summary>
        /// Set password for account (for users who used external provider and want to setup a local login)
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        Task<OperationResult> SetPasswordAsync(SetPasswordModel model);


        /// <summary>
        /// Change user email
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        Task<OperationResult> ChangeEmailAsync(ChangeEmailModel model);

        /// <summary>
        /// Permantently delete the user account
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        Task<OperationResult> DeleteAccountAsync(DeleteAccountModel model);
    }

    /// <summary>
    /// Implementation of <see cref="IAccountService"/>
    /// </summary>
    public class AccountService : IAccountService
    {
        private readonly HttpClient httpClient;

        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="httpClient"></param>
        public AccountService(HttpClient httpClient)
        {
            this.httpClient = httpClient;
        }

        /// <inheritdoc/> 
        public async Task<bool> GetHasPasswordAsync()
        {
            // return await JsonSerializer.DeserializeAsync<bool>
            //           (await httpClient.GetStreamAsync($"api/account/haspassword"));

            var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("https://localhost:7129/api/account/haspassword"),
                Headers = {
                    // { HttpRequestHeader.Authorization.ToString(), "Bearer token" },
                    { HttpRequestHeader.Accept.ToString(), "application/xml" },
                    { HttpRequestHeader.AcceptCharset.ToString(), "utf-8"}
                }
            };

            var response = await httpClient.SendAsync(httpRequestMessage);
            XmlSerializer serializer = new(typeof(Boolean));

            // XmlReaderSettings settings = new();
            // settings.DtdProcessing = DtdProcessing.Parse;
            bool HasPassword;

            var xml = response.Content.ReadAsStringAsync().Result; 
            // Console.WriteLine(xml);           
            using (StringReader reader = new(xml))
            {
                HasPassword = (bool)serializer.Deserialize(reader);

            }

            // using (Stream stream = response.Content.ReadAsStreamAsync().Result)
            // {
            //     HasPassword = (bool)serializer.Deserialize(stream);
            // }

            return HasPassword;
            // return await response.Content.ReadFromJsonAsync<bool>();

        }

        /// <inheritdoc/> 
        public async Task<OperationResult> ChangePasswordAsync(ChangePasswordModel model)
        {
            var result = await httpClient.PostAsJsonAsync<ChangePasswordModel>($"api/account/password/change", model);
            return await OperationResult.FromResponseAsync(result);
        }


        /// <inheritdoc/> 
        public async Task<OperationResult> SetPasswordAsync(SetPasswordModel model)
        {
            var result = await httpClient.PostAsJsonAsync<SetPasswordModel>($"api/account/password/set", model);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> ChangeEmailAsync(ChangeEmailModel model)
        {
            var result = await httpClient.PostAsJsonAsync<ChangeEmailModel>($"api/account/email/change", model);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> ResendEmailConfirmationAsync(ResendEmailConfirmationModel model)
        {
            var result = await httpClient.PostAsJsonAsync<ResendEmailConfirmationModel>($"api/account/email/resendconfirm", model);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> SendPasswordResetLinkAsync(ForgotPasswordModel model)
        {
            var result = await httpClient.PostAsJsonAsync<ForgotPasswordModel>($"api/account/password/sendresetlink", model);
            return await OperationResult.FromResponseAsync(result);
        }

        /// <inheritdoc/>
        public async Task<OperationResult> DeleteAccountAsync(DeleteAccountModel model)
        {
            var result = await httpClient.PostAsJsonAsync<DeleteAccountModel>($"api/account/delete", model);
            return await OperationResult.FromResponseAsync(result);
        }
    }
}
