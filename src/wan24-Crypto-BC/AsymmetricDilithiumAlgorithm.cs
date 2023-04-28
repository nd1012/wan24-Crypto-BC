using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;
using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricDilithiumAlgorithm : AsymmetricAlgorithmBase<AsymmetricDilithiumPublicKey, AsymmetricDilithiumPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "CRYSTALSDILITHIUM";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 3;
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
        static AsymmetricDilithiumAlgorithm()
        {
            _AllowedKeySizes = new List<int>()
            {
                512,
                768,
                1024
            }.AsReadOnly();
            Instance = new();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricDilithiumAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static AsymmetricDilithiumAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => false;

        /// <inheritdoc/>
        public override ReadOnlyCollection<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override AsymmetricDilithiumPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                DilithiumKeyPairGenerator keyGen = new();
                keyGen.Init(new DilithiumKeyGenerationParameters(new SecureRandom(new RandomGenerator()), AsymmetricDilithiumHelper.GetParameters(options.AsymmetricKeyBits)));
                return new(keyGen.GenerateKeyPair());
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
