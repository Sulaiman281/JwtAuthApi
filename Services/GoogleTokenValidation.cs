using Newtonsoft.Json.Linq;

namespace JwtAuthApi.Services
{
    public class GoogleTokenValidation
    {
        public static async Task<string?> ValidateGoogleToken(string token)
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync($"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={token}");

            if (!response.IsSuccessStatusCode)
            {
                return String.Empty;
            }

            var content = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(content);

            if (json == null) return String.Empty;

            if (json.ContainsKey("error_description"))
            {
                return String.Empty;
            }

            return json["email"]?.ToString(); ;
        }
    }
}