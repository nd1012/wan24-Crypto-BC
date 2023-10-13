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
            // Asymmetric
            AsymmetricHelper.Algorithms[AsymmetricKyberAlgorithm.ALGORITHM_NAME] = AsymmetricKyberAlgorithm.Instance;
            //FIXME PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo doesn't support FrodoPrivateKeyParameters !? (waiting for an update of the NuGet package at present)
            //AsymmetricHelper.Algorithms[AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME] = AsymmetricFrodoKemAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricDilithiumAlgorithm.ALGORITHM_NAME] = AsymmetricDilithiumAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricFalconAlgorithm.ALGORITHM_NAME] = AsymmetricFalconAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME] = AsymmetricSphincsPlusAlgorithm.Instance;
            // ChaCha20
            EncryptionHelper.Algorithms[EncryptionChaCha20Algorithm.ALGORITHM_NAME] = EncryptionChaCha20Algorithm.Instance;
            CryptoProfiles.Registered[EncryptionChaCha20Algorithm.PROFILE_CHACHA20_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionChaCha20Algorithm.ALGORITHM_NAME);
            // XSalsa20
            EncryptionHelper.Algorithms[EncryptionXSalsa20Algorithm.ALGORITHM_NAME] = EncryptionXSalsa20Algorithm.Instance;
            CryptoProfiles.Registered[EncryptionXSalsa20Algorithm.PROFILE_XSALSA20_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionXSalsa20Algorithm.ALGORITHM_NAME);
            // AES-256-GCM
            EncryptionHelper.Algorithms[EncryptionAes256GcmAlgorithm.ALGORITHM_NAME] = EncryptionAes256GcmAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionAes256GcmAlgorithm.PROFILE_AES256GCM_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionAes256GcmAlgorithm.ALGORITHM_NAME);
            // Serpent 256 CBC
            EncryptionHelper.Algorithms[EncryptionSerpent256CbcAlgorithm.ALGORITHM_NAME] = EncryptionSerpent256CbcAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionSerpent256CbcAlgorithm.PROFILE_SERPENT256CBC_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionSerpent256CbcAlgorithm.ALGORITHM_NAME);
            // Serpent 256 GCM
            EncryptionHelper.Algorithms[EncryptionSerpent256GcmAlgorithm.ALGORITHM_NAME] = EncryptionSerpent256GcmAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionSerpent256GcmAlgorithm.PROFILE_SERPENT256GCM_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionSerpent256GcmAlgorithm.ALGORITHM_NAME);
            // Twofish 256 CBC
            EncryptionHelper.Algorithms[EncryptionTwofish256CbcAlgorithm.ALGORITHM_NAME] = EncryptionTwofish256CbcAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionTwofish256CbcAlgorithm.PROFILE_TWOFISH256CBC_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionTwofish256CbcAlgorithm.ALGORITHM_NAME);
            // Twofish 256 GCM
            EncryptionHelper.Algorithms[EncryptionTwofish256GcmAlgorithm.ALGORITHM_NAME] = EncryptionTwofish256GcmAlgorithm.Instance;
            CryptoProfiles.Registered[EncryptionTwofish256GcmAlgorithm.PROFILE_TWOFISH256GCM_RAW] = new CryptoOptions()
                .IncludeNothing()
                .WithoutCompression()
                .WithoutMac()
                .WithEncryptionAlgorithm(EncryptionTwofish256GcmAlgorithm.ALGORITHM_NAME);
            // Hash
            HashHelper.Algorithms[HashSha3_256Algorithm.ALGORITHM_NAME] = HashSha3_256Algorithm.Instance;
            HashHelper.Algorithms[HashSha3_384Algorithm.ALGORITHM_NAME] = HashSha3_384Algorithm.Instance;
            HashHelper.Algorithms[HashSha3_512Algorithm.ALGORITHM_NAME] = HashSha3_512Algorithm.Instance;
            // MAC
            MacHelper.Algorithms[MacHmacSha3_256Algorithm.ALGORITHM_NAME] = MacHmacSha3_256Algorithm.Instance;
            MacHelper.Algorithms[MacHmacSha3_384Algorithm.ALGORITHM_NAME] = MacHmacSha3_384Algorithm.Instance;
            MacHelper.Algorithms[MacHmacSha3_512Algorithm.ALGORITHM_NAME] = MacHmacSha3_512Algorithm.Instance;
            // PQ
            CryptoHelper.OnForcePostQuantum += (e) =>
            {
                if (CryptoHelper.StrictPostQuantumSafety)
                {
                    if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum)
                    {
                        AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    }
                    else if(!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? true))
                    {
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    }
                    if (!AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum)
                    {
                        AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                    }
                    else if (!(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? true))
                    {
                        HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                    }
                }
                else
                {
                    if(AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                    {
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    }
                    else if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum)
                    {
                        if (!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                            HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm;
                        AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricKyberAlgorithm.Instance;
                    }
                    if (AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                    {
                        HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                    }
                    else if (!AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum)
                    {
                        if (!(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                            HybridAlgorithmHelper.SignatureAlgorithm = AsymmetricHelper.DefaultSignatureAlgorithm;
                        AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricDilithiumAlgorithm.Instance;
                    }
                }
            };
        }
    }
}
