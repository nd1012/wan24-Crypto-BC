using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed25519 asymmetric private key
    /// </summary>
    public sealed record class AsymmetricEd25519PrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase<
            AsymmetricEd25519PublicKey,
            AsymmetricEd25519Algorithm,
            Ed25519PublicKeyParameters,
            Ed25519PrivateKeyParameters,
            Ed25519Signer,
            AsymmetricEd25519PrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEd25519PrivateKey() : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricEd25519PrivateKey(byte[] keyData) : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricEd25519PrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Create a XEd25519 private key instance
        /// </summary>
        /// <returns>XEd25519 private key (don't forget to dispose!)</returns>
        public AsymmetricXEd25519PrivateKey CreateXEd25519PrivateKey()
        {
            EnsureUndisposed();
            if (Keys is null) throw new InvalidOperationException();
            using SecureByteArrayRefStruct privateKey = new(((Ed25519PrivateKeyParameters)Keys.Private).GetEncoded());
            return new(new AsymmetricCipherKeyPair(
                new Ed25519PublicKeyParameters(((Ed25519PublicKeyParameters)Keys.Public).GetEncoded()),
                new Ed25519PrivateKeyParameters(privateKey.Array)
                ));
        }

        /// <inheritdoc/>
        protected override Ed25519PublicKeyParameters GetPublicKey(Ed25519PrivateKeyParameters privateKey) => privateKey.GeneratePublicKey();

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
        public static implicit operator AsymmetricEd25519PublicKey(AsymmetricEd25519PrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricEd25519PrivateKey(byte[] data) => Import<AsymmetricEd25519PrivateKey>(data);
    }
}
