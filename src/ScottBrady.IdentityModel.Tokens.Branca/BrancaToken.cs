namespace ScottBrady.IdentityModel.Tokens.Branca
{
#pragma warning disable 618
    public class BrancaToken : ScottBrady.IdentityModel.Tokens.BrancaToken
#pragma warning restore 618
    {
        public BrancaToken(string payload, uint timestamp) : base(payload, timestamp)
        {
        }
    }
}