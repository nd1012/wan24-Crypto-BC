using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;
using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricSphincsPlusAlgorithm : AsymmetricAlgorithmBase<AsymmetricSphincsPlusPublicKey, AsymmetricSphincsPlusPrivateKey>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SPHINCSPLUS";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 5;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
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
        static AsymmetricSphincsPlusAlgorithm()
        {
            _AllowedKeySizes = new List<int>()
            {
                128,
                192,
                256
            }.AsReadOnly();
            Instance = new();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) => _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = DEFAULT_KEY_SIZE;

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static AsymmetricSphincsPlusAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override AsymmetricAlgorithmUsages Usages => USAGES;

        /// <inheritdoc/>
        public override bool IsEllipticCurveAlgorithm => false;

        /// <inheritdoc/>
        public override ReadOnlyCollection<int> AllowedKeySizes => _AllowedKeySizes;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override AsymmetricSphincsPlusPrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                SphincsPlusKeyPairGenerator keyGen = new();
                keyGen.Init(new SphincsPlusKeyGenerationParameters(new SecureRandom(new RandomGenerator()), AsymmetricSphincsPlusHelper.GetParameters(options.AsymmetricKeyBits)));
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
