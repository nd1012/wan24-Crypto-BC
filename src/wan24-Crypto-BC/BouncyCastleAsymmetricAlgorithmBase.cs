﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric algorithm
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tPrivate">Private key type</typeparam>
    /// <typeparam name="tKeyGen">Key generator type</typeparam>
    /// <typeparam name="tKeyGenParam">Key generator parameters type</typeparam>
    /// <typeparam name="tParam">Key parameters type</typeparam>
    /// <typeparam name="tPublicKey">Public key type</typeparam>
    /// <typeparam name="tPrivateKey">Private key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricAlgorithmBase<tPublic, tPrivate, tKeyGen, tKeyGenParam, tParam, tPublicKey, tPrivateKey, tFinal>
        : BouncyCastleAsymmetricAlgorithmBase<tPublic, tPrivate, tKeyGenParam, tParam, tPublicKey, tPrivateKey, tFinal>
        where tPublic : BouncyCastleAsymmetricPublicKeyBase<tFinal, tPublicKey, tPublic>, new()
        where tPrivate : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tFinal, tPublicKey, tPrivateKey, tPrivate>, new()
        where tKeyGen : IAsymmetricCipherKeyPairGenerator, new()
        where tKeyGenParam : KeyGenerationParameters
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
        where tFinal : BouncyCastleAsymmetricAlgorithmBase<tPublic, tPrivate, tKeyGen, tKeyGenParam, tParam, tPublicKey, tPrivateKey, tFinal>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        /// <param name="usages">Algorithm usages</param>
        /// <param name="isEllipticCurveAlgorithm">Is an elliptic curve algorithm?</param>
        /// <param name="allowedKeySizes">Allowed key sizes in bits</param>
        /// <param name="isPostQuantum">Is a post quantum-safe algorithm?</param>
        /// <param name="defaultKeySize">Default key size in bits</param>
        protected BouncyCastleAsymmetricAlgorithmBase(
            string name,
            int value,
            AsymmetricAlgorithmUsages usages,
            bool isEllipticCurveAlgorithm,
            FrozenSet<int> allowedKeySizes,
            bool isPostQuantum,
            int defaultKeySize
            )
            : base(name, value, usages, isEllipticCurveAlgorithm, allowedKeySizes, isPostQuantum, defaultKeySize)
        { }

        /// <inheritdoc/>
        public override tPrivate CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                tKeyGen keyGen = new();
                keyGen.Init(CreateKeyGenParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance()), GetEngineParameters(options), options));
                return Activator.CreateInstance(typeof(tPrivate), keyGen.GenerateKeyPair()) as tPrivate
                    ?? throw new InvalidProgramException($"Failed to instance asymmetric private key {typeof(tPrivate)}");
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

    /// <summary>
    /// Base class for a Bouncy Castle asymmetric algorithm
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tPrivate">Private key type</typeparam>
    /// <typeparam name="tKeyGenParam">Key generator parameters type</typeparam>
    /// <typeparam name="tParam">Key parameters type</typeparam>
    /// <typeparam name="tPublicKey">Public key type</typeparam>
    /// <typeparam name="tPrivateKey">Private key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricAlgorithmBase<tPublic, tPrivate, tKeyGenParam, tParam, tPublicKey, tPrivateKey, tFinal>
        : AsymmetricAlgorithmBase<tPublic, tPrivate>
        where tPublic : BouncyCastleAsymmetricPublicKeyBase<tFinal, tPublicKey, tPublic>, new()
        where tPrivate : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tFinal, tPublicKey, tPrivateKey, tPrivate>, new()
        where tKeyGenParam : KeyGenerationParameters
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
        where tFinal : BouncyCastleAsymmetricAlgorithmBase<tPublic, tPrivate, tKeyGenParam, tParam, tPublicKey, tPrivateKey, tFinal>
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleAsymmetricAlgorithmBase() => Instance = (tFinal)Activator.CreateInstance(typeof(tFinal), nonPublic: true)!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        /// <param name="usages">Algorithm usages</param>
        /// <param name="isEllipticCurveAlgorithm">Is an elliptic curve algorithm?</param>
        /// <param name="allowedKeySizes">Allowed key sizes in bits</param>
        /// <param name="isPostQuantum">Is a post quantum-safe algorithm?</param>
        /// <param name="defaultKeySize">Default key size in bits</param>
        protected BouncyCastleAsymmetricAlgorithmBase(
            string name,
            int value,
            AsymmetricAlgorithmUsages usages,
            bool isEllipticCurveAlgorithm,
            FrozenSet<int> allowedKeySizes,
            bool isPostQuantum,
            int defaultKeySize
            )
            : base(name, value)
        {
            Usages = usages;
            IsEllipticCurveAlgorithm = isEllipticCurveAlgorithm;
            AllowedKeySizes = allowedKeySizes;
            IsPostQuantum = isPostQuantum;
            _DefaultOptions.AsymmetricKeyBits = DefaultKeySize = defaultKeySize;
        }

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static tFinal Instance { get; }

        /// <inheritdoc/>
        public sealed override AsymmetricAlgorithmUsages Usages { get; }

        /// <inheritdoc/>
        public sealed override bool IsEllipticCurveAlgorithm { get; }

        /// <inheritdoc/>
        public sealed override FrozenSet<int> AllowedKeySizes { get; }

        /// <inheritdoc/>
        public sealed override bool IsPostQuantum { get; }

        /// <inheritdoc/>
        public override tPrivate DeserializePrivateKeyV1(byte[] keyData) => throw new NotSupportedException();

        /// <summary>
        /// Get the cipher engine parameters
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Parameters</returns>
        protected abstract tParam GetEngineParameters(CryptoOptions options);

        /// <summary>
        /// Create key generator parameters
        /// </summary>
        /// <param name="random">Random</param>
        /// <param name="parameters">Engine parameters</param>
        /// <param name="options">Options</param>
        /// <returns>Key generator parameters</returns>
        protected virtual tKeyGenParam CreateKeyGenParameters(SecureRandom random, tParam parameters, CryptoOptions options)
            => Activator.CreateInstance(typeof(tKeyGenParam), random, parameters) as tKeyGenParam
                ?? throw new InvalidProgramException($"Failed to instance key generation parameters {typeof(tKeyGenParam)}");

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(tFinal), Instance.Name);
    }
}
