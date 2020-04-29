using Org.BouncyCastle.Crypto.Engines;

namespace ScottBrady.Identity.BouncyCastle
{
    public class XChaChaEngine : ChaChaEngine
    {
        public XChaChaEngine() : base(20) { }

        public override string AlgorithmName => "XChaCha20";

        protected override int NonceSize => 24;
    }
}