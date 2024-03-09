using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// X448 asymmetric algorithm (224 bit security))
    /// </summary>
    public sealed record class AsymmetricX448Algorithm
         : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricX448PublicKey,
            AsymmetricX448PrivateKey,
            X448KeyPairGenerator,
            X448KeyGenerationParameters,
            AsymmetricKeyParameter,
            X448PublicKeyParameters,
            X448PrivateKeyParameters,
            AsymmetricX448Algorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "X448";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 11;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 456;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "X448";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricX448Algorithm() => _AllowedKeySizes = new List<int>()
        {
            448,
            456
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricX448Algorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override AsymmetricX448PrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                X448KeyPairGenerator keyGen = new();
                keyGen.Init(new X448KeyGenerationParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance())));
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
