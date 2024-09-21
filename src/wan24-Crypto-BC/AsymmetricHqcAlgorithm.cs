using Org.BouncyCastle.Pqc.Crypto.Hqc;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HQC asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricHqcAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricHqcPublicKey,
            AsymmetricHqcPrivateKey,
            HqcKeyPairGenerator,
            HqcKeyGenerationParameters,
            HqcParameters,
            HqcPublicKeyParameters,
            HqcPrivateKeyParameters,
            AsymmetricHqcAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HQC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 16;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = long.MaxValue;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HQC";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricHqcAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,// 128 bit security
            192,// 192 bit security
            256// 256 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricHqcAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        protected override HqcParameters GetEngineParameters(CryptoOptions options) => AsymmetricHqcHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
