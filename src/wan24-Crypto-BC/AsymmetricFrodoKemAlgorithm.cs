using Org.BouncyCastle.Pqc.Crypto.Frodo;
using System.Collections.ObjectModel;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEM asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricFrodoKemAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricFrodoKemPublicKey,
            AsymmetricFrodoKemPrivateKey,
            FrodoKeyPairGenerator,
            FrodoKeyGenerationParameters,
            FrodoParameters,
            FrodoPublicKeyParameters,
            FrodoPrivateKeyParameters,
            AsymmetricFrodoKemAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "FRODOKEM";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 6;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricFrodoKemAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,
            192,
            256
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFrodoKemAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        protected override FrodoParameters GetEngineParameters(CryptoOptions options) => AsymmetricFrodoKemHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
