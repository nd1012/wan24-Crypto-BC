using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric private key
    /// </summary>
    public sealed class AsymmetricKyberPrivateKey
        : BouncyCastleAsymmetricPrivateKeyExchangeKeyBase<
            AsymmetricKyberPublicKey, 
            AsymmetricKyberAlgorithm, 
            KyberPublicKeyParameters, 
            KyberPrivateKeyParameters, 
            KyberKemGenerator, 
            KyberKemExtractor, 
            AsymmetricKyberPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricKyberPrivateKey() : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricKyberPrivateKey(byte[] keyData) : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricKyberPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME, keys) { }
    }
}
