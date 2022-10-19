namespace Simple_WebAPI.Models
{
    public class RefreshTokenRequest
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Token { get; set; }   
    }
}
