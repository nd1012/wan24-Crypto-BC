using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// EC Diffie Hellman asymmetric private key
    /// </summary>
    public sealed record class AsymmetricBcEcDiffieHellmanPrivateKey
        : BouncyCastleAsymmetricNonPqcPrivateKeyBase<
            AsymmetricBcEcDiffieHellmanPublicKey,
            AsymmetricBcEcDiffieHellmanAlgorithm,
            ECPublicKeyParameters,
            ECPrivateKeyParameters,
            AsymmetricBcEcDiffieHellmanPrivateKey
            >, IKeyExchangePrivateKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBcEcDiffieHellmanPrivateKey() : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBcEcDiffieHellmanPrivateKey(byte[] keyData) : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricBcEcDiffieHellmanPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public AsymmetricBcEcDiffieHellmanPrivateKey(ECPrivateKeyParameters privateKey) : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME, privateKey) { }

        /// <inheritdoc/>
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                Algorithm.EnsureAllowed();
                EnsureAllowedCurve();
                publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
                if (publicKey is not AsymmetricBcEcDiffieHellmanPublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                return (DeriveKey(publicKey), PublicKey.KeyData.Array.CloneArray());
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData() => GetKeyExchangeData();

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData)
        {
            try
            {
                EnsureUndisposed();
                EnsurePqcRequirement();
                using AsymmetricBcEcDiffieHellmanPublicKey publicKey = new(keyExchangeData);
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
                EnsurePqcRequirement();
                if (publicKey is not AsymmetricBcEcDiffieHellmanPublicKey key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                ECDHBasicAgreement agreement = new();
                agreement.Init(PrivateKey);
                BigInteger secret = agreement.CalculateAgreement(key.PublicKey);
                try
                {
                    using SecureByteArrayRefStruct sharedSecret = new(secret.ToByteArray());
                    using SecureByteArrayRefStruct normalizedSecret = new(len: (Bits + 7) / 8);
                    sharedSecret.Span[Math.Max(0, sharedSecret.Length - normalizedSecret.Length)..]
                        .CopyTo(normalizedSecret.Span.Slice(Math.Max(0, normalizedSecret.Length - sharedSecret.Length), Math.Min(sharedSecret.Length, normalizedSecret.Length)));
                    return HashHelper.GetAlgorithm(HashSha256Algorithm.ALGORITHM_NAME).Hash(normalizedSecret.Array);
                }
                finally
                {
                    secret.ClearPrivateByteArrayFields();
                }
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

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

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricBcEcDiffieHellmanPublicKey(AsymmetricBcEcDiffieHellmanPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricBcEcDiffieHellmanPrivateKey(byte[] data) => Import<AsymmetricBcEcDiffieHellmanPrivateKey>(data);
    }
}
