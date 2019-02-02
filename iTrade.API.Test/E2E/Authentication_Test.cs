using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace iTrade.API.Test.E2E
{
    [TestClass]
    public class Authentication_Test
    {
        private static HttpClient _client;

        [ClassInitialize]
        public static void BeforeAll(TestContext context)
        {
            _client = new WebApplicationFactory<Startup>().CreateClient();
        }

        [TestMethod]
        public async Task TestPasswordFlow()
        {
            var reqPayload = new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("client_id", "itrade-web"),
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", "Admin"),
                    new KeyValuePair<string, string>("password", "Test123"),
                });

            var httpResponse = await _client.PostAsync("connect/token", reqPayload);

            httpResponse.EnsureSuccessStatusCode();

            var stringResponse = await httpResponse.Content.ReadAsStringAsync();
            var response = JsonConvert.DeserializeAnonymousType(stringResponse, new
            {
                token_type = string.Empty,
                access_token = string.Empty,
                expires_in = 0,
            });

            response.token_type.Should().Be("Bearer");
            response.access_token.Should().NotBeEmpty();
            response.expires_in.Should().BeCloseTo(3600, 1);
        }

        [TestMethod]
        public async Task TestRefreshFlow()
        {
            var tokenReqPayload = new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("client_id", "itrade-web"),
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", "Admin"),
                    new KeyValuePair<string, string>("password", "Test123"),
                    new KeyValuePair<string, string>("scope", "offline_access")
                });

            var tokenHttpResponse = await _client.PostAsync("connect/token", tokenReqPayload);

            tokenHttpResponse.EnsureSuccessStatusCode();

            var tokenStrResponse = await tokenHttpResponse.Content.ReadAsStringAsync();
            var tokenResponse = JsonConvert.DeserializeAnonymousType(tokenStrResponse, new
            {
                token_type = string.Empty,
                access_token = string.Empty,
                expires_in = 0,
                refresh_token = string.Empty
            });

            tokenResponse.token_type.Should().Be("Bearer");
            tokenResponse.access_token.Should().NotBeEmpty();
            tokenResponse.expires_in.Should().Be(3600);
            tokenResponse.refresh_token.Should().NotBeEmpty();

            var refreshReqPayload = new FormUrlEncodedContent(
                new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("client_id", "itrade-web"),
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", tokenResponse.refresh_token)
                });

            var refreshHttpResponse = await _client.PostAsync("connect/token", refreshReqPayload);

            refreshHttpResponse.EnsureSuccessStatusCode();

            var refreshStrResponse = await refreshHttpResponse.Content.ReadAsStringAsync();
            var refreshResponse = JsonConvert.DeserializeAnonymousType(refreshStrResponse, new
            {
                token_type = string.Empty,
                access_token = string.Empty,
                expires_in = 0,
                scope = string.Empty
            });

            refreshResponse.scope.Should().Be("offline_access");
            refreshResponse.token_type.Should().Be("Bearer");
            refreshResponse.access_token.Should().NotBeEmpty();
            refreshResponse.expires_in.Should().Be(3600);
        }

        [TestMethod]
        public async Task TestAuthorization()
        {
            var protectedUrl = "api/values/protected";

            var req = await _client.GetAsync(protectedUrl);

            req.StatusCode.Should().Be(401);  // 401 - Unauthorized

            var reqPayload = new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                            new KeyValuePair<string, string>("client_id", "itrade-web"),
                            new KeyValuePair<string, string>("grant_type", "password"),
                            new KeyValuePair<string, string>("username", "Admin"),
                            new KeyValuePair<string, string>("password", "Test123"),
            });

            var httpResponse = await _client.PostAsync("connect/token", reqPayload);

            var stringResponse = await httpResponse.Content.ReadAsStringAsync();
            var response = JsonConvert.DeserializeAnonymousType(stringResponse, new
            {
                token_type = string.Empty,
                access_token = string.Empty,
                expires_in = 0,
            });

            using (var protectedReqWithToken = new HttpRequestMessage(HttpMethod.Get, protectedUrl))
            {
                protectedReqWithToken.Headers.Authorization = new AuthenticationHeaderValue("Bearer", response.access_token);
                var auhenticatedResponse = await _client.SendAsync(protectedReqWithToken);

                auhenticatedResponse.EnsureSuccessStatusCode();
            }
        }
    }
}
