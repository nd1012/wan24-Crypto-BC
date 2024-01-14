using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric private key
    /// </summary>
    public sealed record class AsymmetricKyberPrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
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

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys == null) return;
            Keys.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys == null) return;
            Keys.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricKyberPublicKey(AsymmetricKyberPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricKyberPrivateKey(byte[] data) => Import<AsymmetricKyberPrivateKey>(data);
    }
}
