using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Falcon;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric FALCON private key
    /// </summary>
    public sealed class AsymmetricFalconPrivateKey
        : BouncyCastleAsymmetricPrivateSignatureKeyBase<
            AsymmetricFalconPublicKey, 
            AsymmetricFalconAlgorithm, 
            FalconPublicKeyParameters, 
            FalconPrivateKeyParameters, 
            FalconSigner, 
            AsymmetricFalconPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFalconPrivateKey() : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFalconPrivateKey(byte[] keyData) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricFalconPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, keys) { }
    }
}
