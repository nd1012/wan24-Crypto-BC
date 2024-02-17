using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Picnic asymmetric private key
    /// </summary>
    public sealed record class AsymmetricPicnicPrivateKey
        : BouncyCastleAsymmetricPqcPrivateSignatureKeyBase<
            AsymmetricPicnicPublicKey,
            AsymmetricPicnicAlgorithm,
            PicnicPublicKeyParameters,
            PicnicPrivateKeyParameters,
            PicnicSigner,
            AsymmetricPicnicPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricPicnicPrivateKey() : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricPicnicPrivateKey(byte[] keyData) : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricPicnicPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData() => SerializeFullKeyData();

        /// <inheritdoc/>
        protected override void DeserializeKeyData() => DeserializeFullKeyData();

        /// <inheritdoc/>
        protected override PicnicPublicKeyParameters GetPublicKey(PicnicPrivateKeyParameters privateKey) => throw new NotSupportedException();

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
        public static implicit operator AsymmetricPicnicPublicKey(AsymmetricPicnicPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricPicnicPrivateKey(byte[] data) => Import<AsymmetricPicnicPrivateKey>(data);
    }
}
