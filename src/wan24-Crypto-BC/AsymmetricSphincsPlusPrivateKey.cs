using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric private key
    /// </summary>
    public sealed class AsymmetricSphincsPlusPrivateKey
        : BouncyCastleAsymmetricPrivateSignatureKeyBase<
            AsymmetricSphincsPlusPublicKey, 
            AsymmetricSphincsPlusAlgorithm, 
            SphincsPlusPublicKeyParameters, 
            SphincsPlusPrivateKeyParameters, 
            SphincsPlusSigner, 
            AsymmetricSphincsPlusPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusPrivateKey() : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSphincsPlusPrivateKey(byte[] keyData) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricSphincsPlusPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keys) { }
    }
}
