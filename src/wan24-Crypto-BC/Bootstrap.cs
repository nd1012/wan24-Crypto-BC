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
            AsymmetricHelper.Algorithms[AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME] = AsymmetricFrodoKemAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricDilithiumAlgorithm.ALGORITHM_NAME] = AsymmetricDilithiumAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricFalconAlgorithm.ALGORITHM_NAME] = AsymmetricFalconAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME] = AsymmetricSphincsPlusAlgorithm.Instance;
            //FIXME PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo doesn't support NtruPrivateKeyParameters !? (waiting for a fix and an update of the NuGet package at present)
            AsymmetricHelper.Algorithms[AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME] = AsymmetricNtruEncryptAlgorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricEd25519Algorithm.ALGORITHM_NAME] = AsymmetricEd25519Algorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricEd448Algorithm.ALGORITHM_NAME] = AsymmetricEd448Algorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricX25519Algorithm.ALGORITHM_NAME] = AsymmetricX25519Algorithm.Instance;
            AsymmetricHelper.Algorithms[AsymmetricX448Algorithm.ALGORITHM_NAME] = AsymmetricX448Algorithm.Instance;
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
            // PQ
            CryptoHelper.OnForcePostQuantum += (e) =>
            {
                if (CryptoHelper.StrictPostQuantumSafety)
                {
                    if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum)
                    {
                        AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricNtruEncryptAlgorithm.Instance;
                    }
                    else if(!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? true))
                    {
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricNtruEncryptAlgorithm.Instance;
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
                        HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricNtruEncryptAlgorithm.Instance;
                    }
                    else if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum)
                    {
                        if (!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                            HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm;
                        AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricNtruEncryptAlgorithm.Instance;
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
