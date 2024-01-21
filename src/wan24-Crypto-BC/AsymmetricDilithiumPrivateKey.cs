using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric private key
    /// </summary>
    public sealed record class AsymmetricDilithiumPrivateKey
        : BouncyCastleAsymmetricPqcPrivateSignatureKeyBase<
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

        /// <inheritdoc/>
        protected override DilithiumPublicKeyParameters GetPublicKey(DilithiumPrivateKeyParameters privateKey) => new(privateKey.Parameters, privateKey.Rho, privateKey.T1);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

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
