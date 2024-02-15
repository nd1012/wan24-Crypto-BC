using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XEd448 asymmetric private key
    /// </summary>
    public sealed record class AsymmetricXEd448PrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase2<
            AsymmetricXEd448PublicKey,
            AsymmetricXEd448Algorithm,
            Ed448PublicKeyParameters,
            Ed448PrivateKeyParameters,
            Ed448Signer,
            AsymmetricXEd448PrivateKey
            >, IKeyExchangePrivateKey
    {
        /// <summary>
        /// X448 key
        /// </summary>
        private AsymmetricX448PrivateKey? X448Key = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricXEd448PrivateKey() : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricXEd448PrivateKey(byte[] keyData) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricXEd448PrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public AsymmetricXEd448PrivateKey(Ed448PrivateKeyParameters privateKey) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME, privateKey) { }

        /// <inheritdoc/>
        public override AsymmetricXEd448PublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys is null) throw new InvalidOperationException();
                    return _PublicKey ??= Activator.CreateInstance(typeof(AsymmetricXEd448PublicKey), Keys.Public, GetX448Key().PublicKey) as AsymmetricXEd448PublicKey
                        ?? throw new InvalidProgramException($"Failed to instance {typeof(AsymmetricXEd448PublicKey)}");
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
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
                if (publicKey is not AsymmetricXEd448PublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                return GetX448Key().GetKeyExchangeData(key._PublicKey2 ?? throw new InvalidOperationException(), options);
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData() => GetKeyExchangeData();

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData) => GetX448Key().DeriveKey(keyExchangeData);

        /// <inheritdoc/>
        public override byte[] DeriveKey(IAsymmetricPublicKey publicKey)
            => publicKey is AsymmetricXEd448PublicKey key
                ? GetX448Key().DeriveKey(key._PublicKey2 as IAsymmetricPublicKey ?? throw new InvalidOperationException())
                : GetX448Key().DeriveKey(publicKey);

        /// <inheritdoc/>
        protected override Ed448PublicKeyParameters GetPublicKey(Ed448PrivateKeyParameters privateKey) => privateKey.GeneratePublicKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();
            X448Key?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();
            X448Key?.Dispose();
        }

        /// <summary>
        /// Get/create the X448 key
        /// </summary>
        /// <returns>X448 key (will be disposed!)</returns>
        private AsymmetricX448PrivateKey GetX448Key()
        {
            EnsureUndisposed();
            if (Keys?.Private is not Ed448PrivateKeyParameters privateKey) throw new InvalidOperationException();
            X448PrivateKeyParameters pk = privateKey.ToX448PrivateKey();
            return X448Key = new(new AsymmetricCipherKeyPair(pk.GeneratePublicKey(), pk));
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricXEd448PublicKey(AsymmetricXEd448PrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricXEd448PrivateKey(byte[] data) => Import<AsymmetricXEd448PrivateKey>(data);
    }
}
