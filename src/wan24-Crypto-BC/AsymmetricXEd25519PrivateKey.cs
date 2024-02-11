using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XEd25519 asymmetric private key
    /// </summary>
    public sealed record class AsymmetricXEd25519PrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase<
            AsymmetricXEd25519PublicKey,
            AsymmetricXEd25519Algorithm,
            Ed25519PublicKeyParameters,
            Ed25519PrivateKeyParameters,
            Ed25519Signer,
            AsymmetricXEd25519PrivateKey
            >, IKeyExchangePrivateKey
    {
        /// <summary>
        /// X25519 key
        /// </summary>
        private AsymmetricX25519PrivateKey? X25519Key = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricXEd25519PrivateKey() : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricXEd25519PrivateKey(byte[] keyData) : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricXEd25519PrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        public override AsymmetricXEd25519PublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys is null) throw new InvalidOperationException();
                    return _PublicKey ??= Activator.CreateInstance(typeof(AsymmetricXEd25519PublicKey), Keys.Public, GetX25519Key().PublicKey) as AsymmetricXEd25519PublicKey
                        ?? throw new InvalidProgramException($"Failed to instance {typeof(AsymmetricXEd25519PublicKey)}");
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

        /// <summary>
        /// Create a Ed25519 private key instance
        /// </summary>
        /// <returns>Ed25519 private key (don't forget to dispose!)</returns>
        public AsymmetricEd25519PrivateKey CreateEd25519PrivateKey() => new(KeyData.Array.CloneArray());

        /// <summary>
        /// Create a X25519 private key instance
        /// </summary>
        /// <returns>X25519 private key (don't forget to dispose!)</returns>
        public AsymmetricX25519PrivateKey CreateX25519PrivateKey() => (AsymmetricX25519PrivateKey)GetX25519Key().GetCopy();

        /// <inheritdoc/>
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
                if (publicKey is not AsymmetricXEd25519PublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                return GetX25519Key().GetKeyExchangeData(key._PublicKey2 ?? throw new InvalidOperationException(), options);
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData() => GetKeyExchangeData();

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData) => GetX25519Key().DeriveKey(keyExchangeData);

        /// <inheritdoc/>
        public override byte[] DeriveKey(IAsymmetricPublicKey publicKey)
            => publicKey is AsymmetricXEd25519PublicKey key
                ? GetX25519Key().DeriveKey(key._PublicKey2 as IAsymmetricPublicKey ?? throw new InvalidOperationException())
                : GetX25519Key().DeriveKey(publicKey);

        /// <inheritdoc/>
        protected override Ed25519PublicKeyParameters GetPublicKey(Ed25519PrivateKeyParameters privateKey) => privateKey.GeneratePublicKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();
            X25519Key?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();
            X25519Key?.Dispose();
        }

        /// <summary>
        /// Get/create the X25519 key
        /// </summary>
        /// <returns>X25519 key (will be disposed!)</returns>
        private AsymmetricX25519PrivateKey GetX25519Key()
        {
            EnsureUndisposed();
            if (Keys?.Private is not Ed25519PrivateKeyParameters privateKey) throw new InvalidOperationException();
            X25519PrivateKeyParameters pk = privateKey.ToX25519PrivateKey();
            return X25519Key = new(new AsymmetricCipherKeyPair(pk.GeneratePublicKey(), pk));
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricXEd25519PublicKey(AsymmetricXEd25519PrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricXEd25519PrivateKey(byte[] data) => Import<AsymmetricXEd25519PrivateKey>(data);
    }
}
