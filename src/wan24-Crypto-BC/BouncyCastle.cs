//TODO Implement ECDH, ECDSA to replace wan24-Crypto algoritms

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
                HybridAlgorithmHelper.MacAlgorithm = MacHelper.DefaultAlgorithm;
            }
            AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
            AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
            EncryptionHelper.DefaultAlgorithm = EncryptionAes256GcmAlgorithm.Instance;
            HashHelper.DefaultAlgorithm = HashSha3_512Algorithm.Instance;
            MacHelper.DefaultAlgorithm = MacHmacSha3_512Algorithm.Instance;
            Pake.DefaultOptions = Pake.DefaultOptions
                .WithMac(MacHmacSha3_512Algorithm.Instance.Name, included: false);
            CryptoOptions pakeCryptoOptions = Pake.DefaultCryptoOptions
                .WithEncryptionAlgorithm(EncryptionAes256GcmAlgorithm.Instance.Name);
            if (pakeCryptoOptions.MacAlgorithm is not null) pakeCryptoOptions.WithMac(MacHmacSha3_512Algorithm.Instance.Name);
            Pake.DefaultCryptoOptions = pakeCryptoOptions;
        }
    }
}
