using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric private key exchange key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tPrivateKey">Internal private key type</typeparam>
    /// <typeparam name="tGenerator">Key generator type</typeparam>
    /// <typeparam name="tExtractor">Key extractor type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract class BouncyCastleAsymmetricPrivateKeyExchangeKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tGenerator, tExtractor, tFinal>
        : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>, IKeyExchangePrivateKey
        where tPublic : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
        where tGenerator : class, IEncapsulatedSecretGenerator
        where tExtractor : class, IEncapsulatedSecretExtractor
        where tFinal : BouncyCastleAsymmetricPrivateKeyExchangeKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tGenerator, tExtractor, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPrivateKeyExchangeKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPrivateKeyExchangeKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricPrivateKeyExchangeKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : base(algorithm, keys) { }

        /// <inheritdoc/>
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureUndisposed();
                publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
                if (publicKey is not tPublic key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                tGenerator generator = Activator.CreateInstance(typeof(tGenerator), new SecureRandom(BouncyCastleRandomGenerator.Instance())) as tGenerator
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tGenerator)}");
                using ISecretWithEncapsulation secret = generator.GenerateEncapsulated(key.PublicKey);
                return (secret.GetSecret(), secret.GetEncapsulation());
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
                tExtractor extractor = Activator.CreateInstance(typeof(tExtractor), PrivateKey) as tExtractor
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tExtractor)}");
                return extractor.ExtractSecret(keyExchangeData);
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
                if (publicKey is not tPublic key) throw new ArgumentException($"Public {Algorithm.Name} key required", nameof(publicKey));
                tGenerator generator = Activator.CreateInstance(typeof(tGenerator), new SecureRandom(BouncyCastleRandomGenerator.Instance())) as tGenerator
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tGenerator)}");
                using ISecretWithEncapsulation secret = generator.GenerateEncapsulated(key.PublicKey);
                return secret.GetSecret();
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
