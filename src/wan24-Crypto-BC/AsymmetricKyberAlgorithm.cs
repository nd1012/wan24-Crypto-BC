using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricKyberAlgorithm : AsymmetricAlgorithmBase<AsymmetricKyberPublicKey, AsymmetricKyberPrivateKey>
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
        static AsymmetricKyberAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            512,
            768,
            1024
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricKyberAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => false;

        /// <inheritdoc/>
        public override ReadOnlyCollection<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override AsymmetricKyberPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            options ??= DefaultOptions;
            options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
            if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
            KyberKeyPairGenerator keyGen = new();
            keyGen.Init(new KyberKeyGenerationParameters(new SecureRandom(new RandomGenerator()), AsymmetricKyberHelper.GetParameters(options.AsymmetricKeyBits)));
            return new(keyGen.GenerateKeyPair());
        }
    }
}
