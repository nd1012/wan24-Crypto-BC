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
            //FIXME PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo doesn't support FrodoPrivateKeyParameters !? (waiting for an update of the NuGet package at present)
            //AsymmetricHelper.Algorithms[AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME] = AsymmetricFrodoKemAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricDilithiumAlgorithm.ALGORITHM_NAME] = AsymmetricDilithiumAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricFalconAlgorithm.ALGORITHM_NAME] = AsymmetricFalconAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME] = AsymmetricSphincsPlusAlgorithm.Instance;
            EncryptionHelper.Algorithms[EncryptionChaCha20Algorithm.ALGORITHM_NAME] = EncryptionChaCha20Algorithm.Instance;
            CryptoProfiles.Registered[EncryptionChaCha20Algorithm.PROFILE_CHACHA20_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithEncryptionAlgorithm(EncryptionChaCha20Algorithm.ALGORITHM_NAME);
            EncryptionHelper.Algorithms[EncryptionXSalsa20Algorithm.ALGORITHM_NAME] = EncryptionXSalsa20Algorithm.Instance;
            CryptoProfiles.Registered[EncryptionXSalsa20Algorithm.PROFILE_XSALSA20_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithEncryptionAlgorithm(EncryptionXSalsa20Algorithm.ALGORITHM_NAME);
            EncryptionHelper.Algorithms[EncryptionAes256GcmAlgorithm.ALGORITHM_NAME] = EncryptionAes256GcmAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionAes256GcmAlgorithm.PROFILE_AES256GCM_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithEncryptionAlgorithm(EncryptionAes256GcmAlgorithm.ALGORITHM_NAME);
            HashHelper.Algorithms[HashSha3_256Algorithm.ALGORITHM_NAME] = HashSha3_256Algorithm.Instance;
            HashHelper.Algorithms[HashSha3_384Algorithm.ALGORITHM_NAME] = HashSha3_384Algorithm.Instance;
            HashHelper.Algorithms[HashSha3_512Algorithm.ALGORITHM_NAME] = HashSha3_512Algorithm.Instance;
            MacHelper.Algorithms[MacHmacSha3_256Algorithm.ALGORITHM_NAME] = MacHmacSha3_256Algorithm.Instance;
            MacHelper.Algorithms[MacHmacSha3_384Algorithm.ALGORITHM_NAME] = MacHmacSha3_384Algorithm.Instance;
            MacHelper.Algorithms[MacHmacSha3_512Algorithm.ALGORITHM_NAME] = MacHmacSha3_512Algorithm.Instance;
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
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    if (!(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                        HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                }
            };
        }
    }
}
