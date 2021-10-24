namespace ScottBrady.IdentityModel.Tokens.Paseto
{
#pragma warning disable 618
    public class PasetoSecurityToken : ScottBrady.IdentityModel.Tokens.PasetoSecurityToken
#pragma warning restore 618
    {
        protected PasetoSecurityToken() { }
        
        public PasetoSecurityToken(PasetoToken token) : base(token) { }
        
    }
}