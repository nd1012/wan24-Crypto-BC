using Org.BouncyCastle.Pqc.Crypto.Picnic;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricPicnicAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricPicnicPublicKey,
            AsymmetricPicnicPrivateKey,
            PicnicKeyPairGenerator,
            PicnicKeyGenerationParameters,
            PicnicParameters,
            PicnicPublicKeyParameters,
            PicnicPrivateKeyParameters,
            AsymmetricPicnicAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "PICNIC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 17;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 128;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Picnic";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricPicnicAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,// 128 bit security
            192,// 192 bit security
            256// 256 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricPicnicAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override PicnicParameters GetEngineParameters(CryptoOptions options) => AsymmetricPicnicHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
