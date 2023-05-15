using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using Newtonsoft.Json;


namespace DodobirdAi.OAuth2Client
{
public class OAuth2Client
{
    private readonly HttpClient _httpClient;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly string _authorizationEndpoint;
    private readonly string _tokenEndpoint;
    private string _accessToken;
    private string _idToken;
    private string _refreshToken;
    private DateTime _accessTokenExpiration;

    private async Task<T> DeserializeResponse<T>(HttpContent content)
    {
        var json = await content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<T>(json);
    }

    public OAuth2Client(string clientId, string clientSecret, string authorizationEndpoint, string tokenEndpoint)
    {
        _clientId = clientId;
        _clientSecret = clientSecret;
        _authorizationEndpoint = authorizationEndpoint;
        _tokenEndpoint = tokenEndpoint;
        _httpClient = new HttpClient();
    }

    public async Task<string> GetAuthorizationUrl(string redirectUri, string scope)
    {
        var state = Guid.NewGuid().ToString("N");
        var authorizeUrl = $"{_authorizationEndpoint}?response_type=code&client_id={_clientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={Uri.EscapeDataString(scope)}&state={Uri.EscapeDataString(state)}";
        return await Task.FromResult(authorizeUrl);
    }

    public async Task<bool> RequestAccessToken(string code, string redirectUri)
    {
        var tokenRequestParameters = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"code", code},
            {"client_id", _clientId},
            {"client_secret", _clientSecret},
            {"redirect_uri", redirectUri}
        };

        
        var response = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(tokenRequestParameters));
        var responseContent = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);

        if (!response.IsSuccessStatusCode)
        {
            return false;
        }
        Console.WriteLine(tokenResponse);

        SetAccessToken(tokenResponse.access_token, tokenResponse.refresh_oken, tokenResponse.id_token, tokenResponse.expire_in);
        return true;
    }

    public async Task<string> GetAccessToken()
    {
        if (IsAccessTokenValid())
        {
            return _accessToken;
        }

        if (!string.IsNullOrEmpty(_refreshToken))
        {
            await RefreshAccessToken();
            return _accessToken;
        }

        throw new InvalidOperationException("Access token is not available. Please authenticate first.");
    }

    private bool IsAccessTokenValid()
    {
        return !string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _accessTokenExpiration;
    }

    private async Task RefreshAccessToken()
    {
        var tokenRequestParameters = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"refresh_token", _refreshToken},
            {"client_id", _clientId},
            {"client_secret", _clientSecret}
        };

        var response = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(tokenRequestParameters));
        var responseContent = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);

        if (response.IsSuccessStatusCode)
        {
            SetAccessToken(tokenResponse.access_token, tokenResponse.refresh_oken, tokenResponse.id_token, tokenResponse.expire_in);
        }
        else
        {
            throw new InvalidOperationException("Failed to refresh access token.");
        }
    }

    private void SetAccessToken(string accessToken, string refreshToken, string idToken,int expiresIn)
    {
        _accessToken = accessToken;
        _refreshToken = refreshToken;
        _idToken = idToken;
        _accessTokenExpiration = DateTime.UtcNow.AddSeconds(expiresIn);
    }

    private class TokenResponse
    {
        public string access_token { get; set; }
        public string refresh_oken { get; set; }

        public string id_token { get; set; }
        public string token_type { get; set; }
        public int expire_in { get; set; }


    }
}
}