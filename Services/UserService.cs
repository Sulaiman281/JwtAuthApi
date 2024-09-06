using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Entity;
using Models;

namespace Services
{
    public interface IUserService
    {
        Task<LoginResponse> Authenticate(LoginRequest request);
        Task<LoginResponse> Register(RegisterRequest request);
        Task<LoginResponse> RefreshToken(string accessToken, string refreshToken);
    }

    public class UserService(JwtService jwtService, UserRepository userRepository) : IUserService
    {
        private readonly JwtService _jwtService = jwtService;
        private readonly UserRepository _userRepository = userRepository;

        public Task<LoginResponse> Register(RegisterRequest request)
        {
            if (ValidPassword(request.Password) == false)
            {
                throw new ArgumentException("Password must be at least 8 characters long, contain at least one uppercase letter and at least one digit.", request.Password);
            }

            // check if email is valid
            if (new EmailAddressAttribute().IsValid(request.Email) == false)
            {
                throw new ArgumentException("Invalid email", request.Email);
            }

            // check if the email is already taken
            if (_userRepository.IsUserExist(request.Email, out User? _))
            {
                throw new ArgumentException("Email already exists", request.Email);
            }

            // generate a random id for the user
            var id = _userRepository.GenerateUniqueId();

            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(request.Password, out passwordHash, out passwordSalt);

            string refreshToken = _jwtService.GenerateRefreshToken(id, out DateTime expirationDate);

            var user = new User
            {
                Id = id,
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email.ToLower(),
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                RefreshToken = refreshToken,
                RefreshTokenExpiryTime = expirationDate
            };

            _userRepository.AddUser(user);

            string token = _jwtService.Generate(user.Id, user.Email, []);
            return Task.FromResult(new LoginResponse { AccessToken = token, RefreshToken = refreshToken });
        }

        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            if (password != null)
            {
                if (string.IsNullOrWhiteSpace(password))
                {
                    throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(password));
                }

                using var hmac = new HMACSHA512();
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
            else
            {
                throw new ArgumentNullException(nameof(password));
            }
        }

        public Task<LoginResponse> Authenticate(LoginRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email))
            {
                throw new ArgumentException("Email cannot be empty", nameof(request.Email));
            }

            if (!_userRepository.IsUserExist(request.Email, out User? user))
            {
                throw new ArgumentException("User not found", request.Email);
            }
#pragma warning disable CS8602 // null user will never reach this point why warning?
            if (VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt) == false)
            {
                throw new ArgumentException("Invalid password", request.Password);
            }
#pragma warning restore CS8602

            user.RefreshToken = _jwtService.GenerateRefreshToken(user.Id, out DateTime expirationDate);
            user.RefreshTokenExpiryTime = expirationDate;

            string token = _jwtService.Generate(user.Id, user.Email, []);

            return Task.FromResult(new LoginResponse { AccessToken = token, RefreshToken = user.RefreshToken });
        }

        private static bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            if (password != null)
            {
                if (string.IsNullOrWhiteSpace(password))
                {
                    throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(password));
                }

                if (storedHash.Length != 64)
                {
                    throw new ArgumentException("Invalid length of password hash (64 bytes expected).", nameof(storedHash));
                }

                if (storedSalt.Length != 128)
                {
                    throw new ArgumentException("Invalid length of password salt (128 bytes expected).", nameof(storedSalt));
                }

                using var hmac = new HMACSHA512(storedSalt);
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                for (var i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i])
                    {
                        return false;
                    }
                }

                return true;
            }

            throw new ArgumentNullException(nameof(password));
        }


        public static bool ValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }

            return password.Length >= 8 && password.Any(char.IsDigit) && password.Any(char.IsUpper);
        }

        public Task<LoginResponse> RefreshToken(string accessToken, string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(accessToken))
            {
                throw new ArgumentException("Token cannot be empty", nameof(refreshToken));
            }

            if (!_jwtService.ValidateToken(accessToken, true))
            {
                throw new ArgumentException("Invalid Access Token", nameof(accessToken));
            }

            int id = _jwtService.GetUserIdFromToken(accessToken) ?? throw new ArgumentException("Invalid Access Token", nameof(accessToken));

            if (!_userRepository.IsUserExist(id, out User? user))
            {
                throw new ArgumentException("User not found", id.ToString());
            }

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            if (!user.RefreshToken.Equals(refreshToken))
#pragma warning restore CS8602 // Dereference of a possibly null reference.
            {
                Console.WriteLine($"User {user.Email} refresh token {refreshToken}");
                throw new ArgumentException("Invalid Refresh Token", nameof(refreshToken));
            }

            if (user.RefreshTokenExpiryTime < DateTime.UtcNow)
            {
                throw new ArgumentException("Refresh Token expired", nameof(refreshToken));
            }

            string rToken = _jwtService.GenerateRefreshToken(user.Id, out DateTime expireDate);
            string aToken = _jwtService.Refresh(accessToken);

            user.RefreshToken = rToken;
            user.RefreshTokenExpiryTime = expireDate;
            _userRepository.UpdateUser(user.Id, user);
            return Task.FromResult(new LoginResponse { AccessToken = aToken, RefreshToken = rToken });
        }
    }
}