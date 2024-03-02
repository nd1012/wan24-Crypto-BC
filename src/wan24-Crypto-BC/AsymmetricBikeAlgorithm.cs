using Org.BouncyCastle.Pqc.Crypto.Bike;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// BIKE asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricBikeAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricBikePublicKey,
            AsymmetricBikePrivateKey,
            BikeKeyPairGenerator,
            BikeKeyGenerationParameters,
            BikeParameters,
            BikePublicKeyParameters,
            BikePrivateKeyParameters,
            AsymmetricBikeAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "BIKE";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 15;
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
        public const string DISPLAY_NAME = "BIKE";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricBikeAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,// 128 bit security
            192,// 192 bit security
            256// 256 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricBikeAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        protected override BikeParameters GetEngineParameters(CryptoOptions options) => AsymmetricBikeHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
