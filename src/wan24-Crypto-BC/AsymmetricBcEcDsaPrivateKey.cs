using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric EC DSA private key
    /// </summary>
    public sealed record class AsymmetricBcEcDsaPrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateKeyBase<
            AsymmetricBcEcDsaPublicKey,
            AsymmetricBcEcDsaAlgorithm,
            ECPublicKeyParameters,
            ECPrivateKeyParameters,
            AsymmetricBcEcDsaPrivateKey
            >, ISignaturePrivateKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBcEcDsaPrivateKey() : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBcEcDsaPrivateKey(byte[] keyData) : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricBcEcDsaPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public AsymmetricBcEcDsaPrivateKey(ECPrivateKeyParameters privateKey) : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME, privateKey) { }

        /// <inheritdoc/>
        protected override ECPublicKeyParameters GetPublicKey(ECPrivateKeyParameters privateKey) => new(privateKey.Parameters.G.Multiply(privateKey.D), privateKey.Parameters);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys?.Private is not ECPrivateKeyParameters privateKey) return;
            privateKey.D.ClearPrivateByteArrayFields();//TODO All fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys?.Private is not ECPrivateKeyParameters privateKey) return;
            privateKey.D.ClearPrivateByteArrayFields();//TODO All fields are private :(
        }

        /// <inheritdoc/>
        public override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                DsaDigestSigner signer = new(new ECDsaSigner(), new NullDigest());
                signer.Init(forSigning: true, PrivateKey);
                signer.BlockUpdate(hash);
                return signer.GenerateSignature();
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricBcEcDsaPublicKey(AsymmetricBcEcDsaPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricBcEcDsaPrivateKey(byte[] data) => Import<AsymmetricBcEcDsaPrivateKey>(data);
    }
}
