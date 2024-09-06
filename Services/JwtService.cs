using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuthApi.Configure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Services
{
    public class JwtService(IOptions<AppSettings> appSettings)
    {
        private readonly JwtSettings _jwtSettings = appSettings.Value.JwtSettings;

        public string Generate(int Id, string email, Dictionary<string, string> extraClaims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Email, email),
                new("Id", Id.ToString())
            };

            foreach (var claim in extraClaims)
            {
                claims.Add(new Claim(claim.Key, claim.Value));
            }

            var token = new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: DateTime.Now.AddMinutes(_jwtSettings.ExpiryInMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string Refresh(string accessToken)
        {
            // Create a dictionary to hold the extracted claims
            var claimsDictionary = GetClaimsFromToken(accessToken);

            string email = claimsDictionary[JwtRegisteredClaimNames.Email];
            int id = int.Parse(claimsDictionary["Id"]);

            return Generate(id, email, []);
        }

        public Dictionary<string, string> GetClaimsFromToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                // Check if the token can be read
                if (!tokenHandler.CanReadToken(token))
                {
                    throw new ArgumentException("Invalid JWT token");
                }

                // Read the token
                var jwtToken = tokenHandler.ReadJwtToken(token);

                // Extract the claims from the JWT
                var claims = jwtToken.Claims;

                var claimsDictionary = new Dictionary<string, string>();

                foreach (var claim in claims)
                {
                    claimsDictionary.Add(claim.Type, claim.Value);
                }

                return claimsDictionary;
            }
            catch
            {
                throw new TokenException(TokenExceptionType.InvalidToken);
            }
        }

        public bool ValidateToken(string token, bool ignoreExpiration = false)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                if (tokenHandler.CanReadToken(token) is not true)
                {
                    throw new TokenException(TokenExceptionType.InvalidToken);
                }

                if (tokenHandler.ReadToken(token) is not JwtSecurityToken securityToken)
                {
                    throw new TokenException(TokenExceptionType.InvalidToken);
                }

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = !ignoreExpiration,  // Set ValidateLifetime based on ignoreExpiration
                    ClockSkew = TimeSpan.Zero
                };


                tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch (SecurityTokenExpiredException)
            {
                if (ignoreExpiration)
                {
                    return true;
                }

                throw new TokenException(TokenExceptionType.TokenExpired);
            }
            catch (Exception)
            {
                throw new TokenException(TokenExceptionType.InvalidToken);
            }
        }


        public Dictionary<string, string> GetClaimsFromToken(string token, string[] claimTypes)
        {
            var claims = GetClaimsFromToken(token);
            return claims.Where(c => claimTypes.Contains(c.Key)).ToDictionary(c => c.Key, c => c.Value);
        }

        public int? GetUserIdFromToken(string token)
        {
            return int.TryParse(GetClaimsFromToken(token)["Id"], out int id) ? id : null;
        }

        public string GetEmailFromToken(string token)
        {
            return GetClaimsFromToken(token)[JwtRegisteredClaimNames.Email];
        }

        // extract extra claims from token
        public Dictionary<string, string> GetExtraClaimsFromToken(string token)
        {
            var claims = GetClaimsFromToken(token);
            claims.Remove("Id");
            claims.Remove(JwtRegisteredClaimNames.Email);
            return claims;
        }

        #region  custom refresh token 
        public string GenerateRefreshToken(int id, out DateTime expirationDate)
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            string token = Convert.ToBase64String(randomNumber);
            expirationDate = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);
            return token;
        }

        #endregion
    }

    public enum TokenExceptionType
    {
        InvalidToken,
        TokenExpired
    }

    public class TokenException(TokenExceptionType type) : Exception(type == TokenExceptionType.InvalidToken ? "Invalid token" : "Token Expired")
    {
        public TokenExceptionType Type { get; } = type;
    }
}