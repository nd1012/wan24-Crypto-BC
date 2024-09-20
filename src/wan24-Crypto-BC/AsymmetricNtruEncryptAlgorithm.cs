using Org.BouncyCastle.Pqc.Crypto.Ntru;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// NTRUEncrypt asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricNtruEncryptAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricNtruEncryptPublicKey,
            AsymmetricNtruEncryptPrivateKey,
            NtruKeyPairGenerator,
            NtruKeyGenerationParameters,
            NtruParameters,
            NtruPublicKeyParameters,
            NtruPrivateKeyParameters,
            AsymmetricNtruEncryptAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "NTRUENCRYPT";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 7;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 701;
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
        public const string DISPLAY_NAME = "NTRUEncrypt";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricNtruEncryptAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            509,// 128 bit security
            677,// 192 bit security
            701,// 256 bit security
            821// 123 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricNtruEncryptAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => false;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        protected override NtruParameters GetEngineParameters(CryptoOptions options) => AsymmetricNtruHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
