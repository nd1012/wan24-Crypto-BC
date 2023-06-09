﻿using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using System.Collections.ObjectModel;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricKyberAlgorithm
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
        public AsymmetricKyberAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KyberParameters GetEngineParameters(CryptoOptions options) => AsymmetricKyberHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
