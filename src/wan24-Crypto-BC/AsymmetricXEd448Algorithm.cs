using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using System.Security;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XEd448 asymmetric algorithm (converts the used Ed448 private key to a X448 private key for key exchange; 224 bit security)
    /// </summary>
    public sealed record class AsymmetricXEd448Algorithm
         : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricXEd448PublicKey,
            AsymmetricXEd448PrivateKey,
            Ed448KeyPairGenerator,
            Ed448KeyGenerationParameters,
            AsymmetricKeyParameter,
            Ed448PublicKeyParameters,
            Ed448PrivateKeyParameters,
            AsymmetricXEd448Algorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "XED448";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 13;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 456;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = long.MaxValue;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature | AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "XEd448";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricXEd448Algorithm() => _AllowedKeySizes = new List<int>()
        {
            448,
            456
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricXEd448Algorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => false;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        public override AsymmetricXEd448PrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                Ed448KeyPairGenerator keyGen = new();
                keyGen.Init(new Ed448KeyGenerationParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance())));
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
