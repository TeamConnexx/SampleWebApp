using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using SampleMvcApp.ViewModels;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;

namespace SampleMvcApp.Controllers
{
    public class AccountController : Controller
    {
        public async Task Login(string returnUrl = "/")
        {

            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                            .WithRedirectUri(returnUrl)
                            .WithAudience("https://dev-idnsrmbt15ylxsip.us.auth0.com/api/v2/")
                            .Build()
                ;

            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            var even = new Auth0WebAppWithAccessTokenEvents();
            }

        private Task OnMissingAccessToken(HttpContext arg)
        {
            throw new NotImplementedException();
        }

        static async Task<string> GetAccessToken()
        {
            using (var httpClient = new HttpClient())
            {
                var tokenEndpoint = "https://dev-idnsrmbt15ylxsip.us.auth0.com/oauth/token";

                var requestBody = new Dictionary<string, string>
                {
                    {"client_id", "f84lPOgyYMCm4qqmrbTRzChkKTWwgOz9"},
                    {"client_secret", "yDhSJMkb408naZbraJJo617FZhaBEpeac-qTGwqXEdmfOoh6SfUrPLOMZCFgoyQ6"},
                    {"audience", "https://dev-idnsrmbt15ylxsip.us.auth0.com/api/v2/"},
                    {"grant_type","client_credentials"}
                };

                var tokenRequestContent = new FormUrlEncodedContent(requestBody);


                var response = await httpClient.PostAsync(tokenEndpoint, tokenRequestContent);

                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }
                var responseContent = await response.Content.ReadAsStringAsync();
                dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
                var accessToken = jsonResponse.access_token;
                return accessToken;
            }
        }

        [Authorize]
        public async Task Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in 
                .WithRedirectUri(Url.Action("Index", "Home"))
                .Build();

            await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public async void CheckLogin()
        {
            using (var httpClient = new HttpClient())
            {
                var authorizeEndpoint = "https://dev-idnsrmbt15ylxsip.us.auth0.com/authorize";

                var requestBody = new
                {
                    client_id = "f84lPOgyYMCm4qqmrbTRzChkKTWwgOz9",
                    response_type = "code",
                    redirect_uri = "http://localhost:3000/callback",
                    prompt = "none",
                };

                var builder = new UriBuilder("https://dev-idnsrmbt15ylxsip.us.auth0.com/authorize");
                builder.Query = $"response_type=code&client_id={requestBody.client_id}&redirect_uri={requestBody.redirect_uri}";

                HttpResponseMessage response = await httpClient.GetAsync(builder.Uri);

                // Check if request was successful
                if (response.IsSuccessStatusCode)
                {
                    // Read response content (if needed)
                    string responseBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(responseBody); // Output the response body
                }
                else
                {
                    Console.WriteLine($"Failed to request authorization. Status code: {response.StatusCode}");
                }
            }
        }

        [Authorize]
        public IActionResult Profile()
        {
            GetAccessToken();
            return View(new UserProfileViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            });
        }


        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
