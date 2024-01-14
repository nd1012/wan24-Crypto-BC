using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// NTRUEncrypt asymmetric private key
    /// </summary>
    public sealed record class AsymmetricNtruEncryptPrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
            AsymmetricNtruEncryptPublicKey,
            AsymmetricNtruEncryptAlgorithm,
            NtruPublicKeyParameters,
            NtruPrivateKeyParameters,
            NtruKemGenerator,
            NtruKemExtractor,
            AsymmetricNtruEncryptPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricNtruEncryptPrivateKey() : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricNtruEncryptPrivateKey(byte[] keyData) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricNtruEncryptPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, keys) { }

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
        public static implicit operator AsymmetricNtruEncryptPublicKey(AsymmetricNtruEncryptPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricNtruEncryptPrivateKey(byte[] data) => Import<AsymmetricNtruEncryptPrivateKey>(data);
    }
}
