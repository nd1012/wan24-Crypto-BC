using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric private key
    /// </summary>
    public sealed record class AsymmetricDilithiumPrivateKey
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

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys == null) return;
            DilithiumPrivateKeyParameters privateKey = (DilithiumPrivateKeyParameters)Keys.Private;
            privateKey.K.Clear();
            privateKey.Rho.Clear();
            privateKey.S1.Clear();
            privateKey.S2.Clear();
            privateKey.T0.Clear();
            privateKey.T1.Clear();
            privateKey.Tr.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys == null) return;
            DilithiumPrivateKeyParameters privateKey = (DilithiumPrivateKeyParameters)Keys.Private;
            privateKey.K.Clear();
            privateKey.Rho.Clear();
            privateKey.S1.Clear();
            privateKey.S2.Clear();
            privateKey.T0.Clear();
            privateKey.T1.Clear();
            privateKey.Tr.Clear();
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
