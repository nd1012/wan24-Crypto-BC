using Org.BouncyCastle.Pqc.Crypto.Ntru;
using System.Collections.ObjectModel;

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
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricNtruEncryptAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            509,
            677,
            701,
            821
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricNtruEncryptAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override NtruParameters GetEngineParameters(CryptoOptions options) => AsymmetricNtruHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
