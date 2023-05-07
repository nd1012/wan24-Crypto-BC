using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric private key
    /// </summary>
    public sealed class AsymmetricDilithiumPrivateKey
        : BouncyCastleAsymmetricPrivateSignatureKeyBase<
            AsymmetricDilithiumPublicKey,
            AsymmetricDilithiumAlgorithm,
            DilithiumPublicKeyParameters,
            DilithiumPrivateKeyParameters,
            DilithiumSigner,
            AsymmetricDilithiumPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricDilithiumPrivateKey() : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricDilithiumPrivateKey(byte[] keyData) : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricDilithiumPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricDilithiumPublicKey(AsymmetricDilithiumPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricDilithiumPrivateKey(byte[] data) => Import<AsymmetricDilithiumPrivateKey>(data);
    }
}
