namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle helper
    /// </summary>
    public static class BouncyCastle
    {
        /// <summary>
        /// Set the implemented algorithms as defaults
        /// </summary>
        /// <param name="useCurrentDefaultAsCounterAlgorithms">Use the current <c>wan24-Crypto</c> defaults as counter algorithms?</param>
        public static void SetDefaults(in bool useCurrentDefaultAsCounterAlgorithms = true)
        {
            //TODO Use NTRU as default asymmetric algorithm for key exchange
            if (useCurrentDefaultAsCounterAlgorithms)
            {
                HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm;
                HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.DefaultSignatureAlgorithm;
            }
            AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
            AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
            EncryptionHelper.DefaultAlgorithm = EncryptionSerpent256CbcAlgorithm.Instance;
            CryptoOptions pakeCryptoOptions = Pake.DefaultCryptoOptions
                .WithEncryptionAlgorithm(EncryptionAes256GcmAlgorithm.Instance.Name);
            Pake.DefaultCryptoOptions = pakeCryptoOptions;
        }

        /// <summary>
        /// Replace .NET algorithms which may not be available on all platforms
        /// </summary>
        public static void ReplaceNetAlgorithms()
        {
            EncryptionHelper.Algorithms[EncryptionAes256CbcAlgorithm.ALGORITHM_NAME] = EncryptionBcAes256CbcAlgorithm.Instance;
            if (EncryptionHelper.DefaultAlgorithm.Value == EncryptionAes256CbcAlgorithm.ALGORITHM_VALUE)
                EncryptionHelper.DefaultAlgorithm = EncryptionBcAes256CbcAlgorithm.Instance;
            HashHelper.Algorithms[HashBcSha3_256Algorithm.ALGORITHM_NAME] = HashBcSha3_256Algorithm.Instance;
            HashHelper.Algorithms[HashBcSha3_384Algorithm.ALGORITHM_NAME] = HashBcSha3_384Algorithm.Instance;
            HashHelper.Algorithms[HashBcSha3_512Algorithm.ALGORITHM_NAME] = HashBcSha3_512Algorithm.Instance;
            HashHelper.Algorithms[HashBcShake128Algorithm.ALGORITHM_NAME] = HashBcShake128Algorithm.Instance;
            HashHelper.Algorithms[HashBcShake256Algorithm.ALGORITHM_NAME] = HashBcShake256Algorithm.Instance;
            switch (HashHelper.DefaultAlgorithm.Value)
            {
                case HashBcSha3_256Algorithm.ALGORITHM_VALUE:
                    HashHelper.DefaultAlgorithm = HashBcSha3_256Algorithm.Instance;
                    break;
                case HashBcSha3_384Algorithm.ALGORITHM_VALUE:
                    HashHelper.DefaultAlgorithm = HashBcSha3_384Algorithm.Instance;
                    break;
                case HashBcSha3_512Algorithm.ALGORITHM_VALUE:
                    HashHelper.DefaultAlgorithm = HashBcSha3_512Algorithm.Instance;
                    break;
            }
            MacHelper.Algorithms[MacBcHmacSha3_256Algorithm.ALGORITHM_NAME] = MacBcHmacSha3_256Algorithm.Instance;
            MacHelper.Algorithms[MacBcHmacSha3_384Algorithm.ALGORITHM_NAME] = MacBcHmacSha3_384Algorithm.Instance;
            MacHelper.Algorithms[MacBcHmacSha3_512Algorithm.ALGORITHM_NAME] = MacBcHmacSha3_512Algorithm.Instance;
            switch (MacHelper.DefaultAlgorithm.Value)
            {
                case MacBcHmacSha3_256Algorithm.ALGORITHM_VALUE:
                    MacHelper.DefaultAlgorithm = MacBcHmacSha3_256Algorithm.Instance;
                    break;
                case MacBcHmacSha3_384Algorithm.ALGORITHM_VALUE:
                    MacHelper.DefaultAlgorithm = MacBcHmacSha3_384Algorithm.Instance;
                    break;
                case MacBcHmacSha3_512Algorithm.ALGORITHM_VALUE:
                    MacHelper.DefaultAlgorithm = MacBcHmacSha3_512Algorithm.Instance;
                    break;
            }
            //TODO Implement ECDH, ECDSA to replace wan24-Crypto algorithms
        }
    }
}
