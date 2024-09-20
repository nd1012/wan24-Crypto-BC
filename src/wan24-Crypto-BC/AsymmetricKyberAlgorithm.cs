using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricKyberAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricKyberPublicKey, 
            AsymmetricKyberPrivateKey, 
            KyberKeyPairGenerator, 
            KyberKeyGenerationParameters, 
            KyberParameters, 
            KyberPublicKeyParameters, 
            KyberPrivateKeyParameters, 
            AsymmetricKyberAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "CRYSTALSKYBER";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 1024;
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
        public const string DISPLAY_NAME = "CRYSTALS-Kyber";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricKyberAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            512,// 128 bit security
            768,// 192 bit security
            1024// 256 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricKyberAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        protected override KyberParameters GetEngineParameters(CryptoOptions options) => AsymmetricKyberHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
