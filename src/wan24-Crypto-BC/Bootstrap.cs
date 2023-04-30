using wan24.Core;

[assembly: Bootstrapper(typeof(wan24.Crypto.BC.Bootstrap), nameof(wan24.Crypto.BC.Bootstrap.Boot))]

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bootstrapper
    /// </summary>
    public static class Bootstrap
    {
        /// <summary>
        /// Boot
        /// </summary>
        public static void Boot()
        {
            AsymmetricHelper.Algorithms[AsymmetricKyberAlgorithm.ALGORITHM_NAME] = AsymmetricKyberAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME] = AsymmetricFrodoKemAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricDilithiumAlgorithm.ALGORITHM_NAME] = AsymmetricDilithiumAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricFalconAlgorithm.ALGORITHM_NAME] = AsymmetricFalconAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME] = AsymmetricSphincsPlusAlgorithm.Instance;
            EncryptionHelper.Algorithms[EncryptionChaCha20Algorithm.ALGORITHM_NAME] = EncryptionChaCha20Algorithm.Instance;
            EncryptionHelper.Algorithms[EncryptionXSalsa20Algorithm.ALGORITHM_NAME] = EncryptionXSalsa20Algorithm.Instance;
            CryptoHelper.OnForcePostQuantum += (e) =>
            {
                if (!EncryptionHelper.DefaultAlgorithm.IsPostQuantum)
                    EncryptionHelper.DefaultAlgorithm = EncryptionChaCha20Algorithm.Instance;
                if (CryptoHelper.StrictPostQuantumSafety)
                {
                    if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum)
                        AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    if (!AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum)
                        AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                }
                else
                {
                    if (!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(AsymmetricKyberAlgorithm.ALGORITHM_NAME);
                    if (!(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                        HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.GetAlgorithm(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME);
                }
            };
        }
    }
}
