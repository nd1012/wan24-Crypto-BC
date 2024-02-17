using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// BIKE asymmetric private key
    /// </summary>
    public sealed record class AsymmetricBikePrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
            AsymmetricBikePublicKey,
            AsymmetricBikeAlgorithm,
            BikePublicKeyParameters,
            BikePrivateKeyParameters,
            BikeKemGenerator,
            BikeKemExtractor,
            AsymmetricBikePrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBikePrivateKey() : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBikePrivateKey(byte[] keyData) : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricBikePrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData() => SerializeFullKeyData();

        /// <inheritdoc/>
        protected override void DeserializeKeyData() => DeserializeFullKeyData();

        /// <inheritdoc/>
        protected override BikePublicKeyParameters GetPublicKey(BikePrivateKeyParameters privateKey) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys?.Private is not BikePrivateKeyParameters privateKey) return;
            privateKey.GetH0().Clear();
            privateKey.GetH1().Clear();
            privateKey.GetSigma().Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys?.Private is not BikePrivateKeyParameters privateKey) return;
            privateKey.GetH0().Clear();
            privateKey.GetH1().Clear();
            privateKey.GetSigma().Clear();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricBikePublicKey(AsymmetricBikePrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricBikePrivateKey(byte[] data) => Import<AsymmetricBikePrivateKey>(data);
    }
}
