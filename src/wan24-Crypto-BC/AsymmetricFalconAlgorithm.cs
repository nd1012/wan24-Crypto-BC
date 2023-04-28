using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Security;
using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FALCON asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricFalconAlgorithm : AsymmetricAlgorithmBase<AsymmetricFalconPublicKey, AsymmetricFalconPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "FALCON";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 4;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 1024;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricFalconAlgorithm()
        {
            _AllowedKeySizes = new List<int>()
            {
                512,
                1024
            }.AsReadOnly();
            Instance = new();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFalconAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static AsymmetricFalconAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => false;

        /// <inheritdoc/>
        public override ReadOnlyCollection<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override AsymmetricFalconPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                FalconKeyPairGenerator keyGen = new();
                keyGen.Init(new FalconKeyGenerationParameters(new SecureRandom(new RandomGenerator()), AsymmetricFalconHelper.GetParameters(options.AsymmetricKeyBits)));
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
    }
}
