using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Tls.Crypto;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed448 asymmetric private key
    /// </summary>
    public sealed record class AsymmetricEd448PrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase2<
            AsymmetricEd448PublicKey,
            AsymmetricEd448Algorithm,
            Ed448PublicKeyParameters,
            Ed448PrivateKeyParameters,
            Ed448Signer,
            AsymmetricEd448PrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEd448PrivateKey() : base(AsymmetricEd448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricEd448PrivateKey(byte[] keyData) : base(AsymmetricEd448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricEd448PrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricEd448Algorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return 456;
                }
                catch (CryptographicException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <inheritdoc/>
        protected override Ed448PublicKeyParameters GetPublicKey(Ed448PrivateKeyParameters privateKey) => privateKey.GeneratePublicKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricEd448PublicKey(AsymmetricEd448PrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEd448PrivateKey(byte[] data) => Import<AsymmetricEd448PrivateKey>(data);
    }
}
