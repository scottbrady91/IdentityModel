namespace ScottBrady.IdentityModel.Branca
{
#pragma warning disable 618
    public class BrancaSecurityToken : ScottBrady.IdentityModel.Tokens.BrancaSecurityToken
#pragma warning restore 618
    {
        public BrancaSecurityToken(Tokens.BrancaToken token) : base(token)
        {
        }
    }
}