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
            //TODO In v2 use NTRU as default asymmetric algorithm for key exchange
            if (useCurrentDefaultAsCounterAlgorithms)
            {
                HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm;
                HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.DefaultSignatureAlgorithm;
                HybridAlgorithmHelper.MacAlgorithm = MacHelper.DefaultAlgorithm;
            }
            AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
            AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
            EncryptionHelper.DefaultAlgorithm = EncryptionSerpent256CbcAlgorithm.Instance;
            HashHelper.DefaultAlgorithm = HashSha3_512Algorithm.Instance;
            MacHelper.DefaultAlgorithm = MacHmacSha3_512Algorithm.Instance;
            Pake.DefaultOptions = Pake.DefaultOptions
                .WithMac(MacHmacSha3_512Algorithm.Instance.Name, included: false);
            CryptoOptions pakeCryptoOptions = Pake.DefaultCryptoOptions
                .WithEncryptionAlgorithm(EncryptionAes256GcmAlgorithm.Instance.Name);
            if (pakeCryptoOptions.MacAlgorithm is not null) pakeCryptoOptions.WithMac(MacHmacSha3_512Algorithm.Instance.Name);
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
            //TODO Implement ECDH, ECDSA to replace wan24-Crypto algoritms
        }
    }
}
