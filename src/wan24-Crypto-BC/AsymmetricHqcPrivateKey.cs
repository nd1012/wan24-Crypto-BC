using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HQC asymmetric private key
    /// </summary>
    public sealed record class AsymmetricHqcPrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
            AsymmetricHqcPublicKey,
            AsymmetricHqcAlgorithm,
            HqcPublicKeyParameters,
            HqcPrivateKeyParameters,
            HqcKemGenerator,
            HqcKemExtractor,
            AsymmetricHqcPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricHqcPrivateKey() : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricHqcPrivateKey(byte[] keyData) : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricHqcPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData() => SerializeFullKeyData();

        /// <inheritdoc/>
        protected override void DeserializeKeyData() => DeserializeFullKeyData();

        /// <inheritdoc/>
        protected override HqcPublicKeyParameters GetPublicKey(HqcPrivateKeyParameters privateKey) => throw new NotSupportedException();

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
        public static implicit operator AsymmetricHqcPublicKey(AsymmetricHqcPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricHqcPrivateKey(byte[] data) => Import<AsymmetricHqcPrivateKey>(data);
    }
}
