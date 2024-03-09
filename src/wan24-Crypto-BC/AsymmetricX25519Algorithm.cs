using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// X25519 asymmetric algorithm (128 bit security))
    /// </summary>
    public sealed record class AsymmetricX25519Algorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricX25519PublicKey,
            AsymmetricX25519PrivateKey,
            X25519KeyPairGenerator,
            X25519KeyGenerationParameters,
            AsymmetricKeyParameter,
            X25519PublicKeyParameters,
            X25519PrivateKeyParameters,
            AsymmetricX25519Algorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "X25519";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 10;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "X25519";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricX25519Algorithm() => _AllowedKeySizes = new List<int>()
        {
            256
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricX25519Algorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override AsymmetricX25519PrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                X25519KeyPairGenerator keyGen = new();
                keyGen.Init(new X25519KeyGenerationParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance())));
                return new(keyGen.GenerateKeyPair());
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

        /// <inheritdoc/>
        protected override AsymmetricKeyParameter GetEngineParameters(CryptoOptions options) => throw new NotSupportedException();
    }
}
