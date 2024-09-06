namespace Entity
{
    public class UserRepository
    {
        private List<User> _users = new List<User>();
        private Dictionary<int, User> _userDictionary = new Dictionary<int, User>();

        public bool IsUserExist(string email, out User? user)
        {
            user = _users.FirstOrDefault(x => x.Email.Equals(email.ToLower()));
            return _users.Any(x => x.Email == email.ToLower());
        }

        public int GenerateUniqueId()
        {
            return _users.Count + 1;
        }

        public void AddUser(User user)
        {
            _users.Add(user);
            _userDictionary.Add(user.Id, user);
        }

        public void UpdateUser(int userId, User user)
        {
            _users.Remove(_userDictionary[userId]);
            _users.Add(user);
            _userDictionary[userId] = user;
        }

        public User GetUser(int userId)
        {
            return _userDictionary[userId];
        }

        public bool IsUserExist(int userId, out User? user)
        {
            return _userDictionary.TryGetValue(userId, out user);
        }
    }
}