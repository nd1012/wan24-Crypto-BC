
//TODO Add v2 SEIPD encryption algorithms as an alternate to AEAD
//TODO Add Argon2 S2K KDF algorithm

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
            if (useCurrentDefaultAsCounterAlgorithms)
            {
                HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm;
                HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.DefaultSignatureAlgorithm;
            }
            AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricNtruEncryptAlgorithm.Instance;
            AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
            EncryptionHelper.DefaultAlgorithm = EncryptionSerpent256CbcAlgorithm.Instance;
            CryptoOptions pakeCryptoOptions = Pake.DefaultCryptoOptions
                .WithEncryptionAlgorithm(EncryptionSerpent256GcmAlgorithm.ALGORITHM_NAME);
            Pake.DefaultCryptoOptions = pakeCryptoOptions;
        }

        /// <summary>
        /// Replace .NET algorithms which may not be available on all platforms
        /// </summary>
        public static void ReplaceNetAlgorithms()
        {
            // Encryption
            EncryptionHelper.Algorithms[EncryptionAes256CbcAlgorithm.ALGORITHM_NAME] = EncryptionBcAes256CbcAlgorithm.Instance;
            switch (EncryptionHelper.DefaultAlgorithm.Value)
            {
                case EncryptionAes256CbcAlgorithm.ALGORITHM_VALUE:
                    EncryptionHelper.DefaultAlgorithm = EncryptionBcAes256CbcAlgorithm.Instance;
                    break;
            }
            // Hashing
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
                case HashBcShake128Algorithm.ALGORITHM_VALUE:
                    HashHelper.DefaultAlgorithm = HashBcShake128Algorithm.Instance;
                    break;
                case HashBcShake256Algorithm.ALGORITHM_VALUE:
                    HashHelper.DefaultAlgorithm = HashBcShake256Algorithm.Instance;
                    break;
            }
            // MAC
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
            // Asymmetric
            AsymmetricHelper.Algorithms[AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME] = AsymmetricBcEcDiffieHellmanAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME] = AsymmetricBcEcDsaAlgorithm.Instance;
            switch (AsymmetricHelper.DefaultSignatureAlgorithm.Value)
            {
                case AsymmetricBcEcDsaAlgorithm.ALGORITHM_VALUE:
                    AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricBcEcDsaAlgorithm.Instance;
                    break;
            }
            switch (AsymmetricHelper.DefaultKeyExchangeAlgorithm.Value)
            {
                case AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_VALUE:
                    AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricBcEcDiffieHellmanAlgorithm.Instance;
                    break;
            }
        }
    }
}
