using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// X448 asymmetric private key
    /// </summary>
    public sealed record class AsymmetricX448PrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateKeyBase<
            AsymmetricX448PublicKey,
            AsymmetricX448Algorithm,
            X448PublicKeyParameters,
            X448PrivateKeyParameters,
            AsymmetricX448PrivateKey
            >, IKeyExchangePrivateKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricX448PrivateKey() : base(AsymmetricX448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricX448PrivateKey(byte[] keyData) : base(AsymmetricX448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricX448PrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricX448Algorithm.ALGORITHM_NAME, keys) { }

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
                if (publicKey is not AsymmetricX448PublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                return (DeriveKey(publicKey), PublicKey.KeyData.Array.CloneArray());
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                using AsymmetricX448PublicKey publicKey = new(keyExchangeData);
                return DeriveKey(publicKey as IAsymmetricPublicKey);
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override byte[] DeriveKey(IAsymmetricPublicKey publicKey)
        {
            try
            {
                EnsureUndisposed();
                if (CryptoHelper.StrictPostQuantumSafety) throw new InvalidOperationException($"Post quantum safety-forced - {Algorithm.Name} isn't post quantum");
                if (publicKey is not AsymmetricX448PublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                X448Agreement agreement = new();
                agreement.Init(PrivateKey);
                byte[] res = new byte[agreement.AgreementSize];
                try
                {
                    agreement.CalculateAgreement(key.PublicKey, res);
                    return res;
                }
                catch
                {
                    res.Clear();
                    throw;
                }
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override X448PublicKeyParameters GetPublicKey(X448PrivateKeyParameters privateKey) => privateKey.GeneratePublicKey();

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
        public static implicit operator AsymmetricX448PublicKey(AsymmetricX448PrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricX448PrivateKey(byte[] data) => Import<AsymmetricX448PrivateKey>(data);
    }
}
