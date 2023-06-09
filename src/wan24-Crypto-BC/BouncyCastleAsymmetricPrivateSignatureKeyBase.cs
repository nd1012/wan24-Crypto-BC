﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric private signature key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tPrivateKey">Internal private key type</typeparam>
    /// <typeparam name="tSigner">Signer type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract class BouncyCastleAsymmetricPrivateSignatureKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tSigner, tFinal>
        : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>, ISignaturePrivateKey
        where tPublic : BouncyCastleAsymmetricPublicSignatureKeyBase<tAlgo, tPublicKey, tSigner, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
        where tSigner : class, IMessageSigner, new()
        where tFinal : BouncyCastleAsymmetricPrivateSignatureKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tSigner, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPrivateSignatureKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPrivateSignatureKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricPrivateSignatureKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : base(algorithm, keys) { }

        /// <inheritdoc/>
        public sealed override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                EnsureUndisposed();
                tSigner signer = new();
                signer.Init(forSigning: true, PrivateKey);
                return signer.GenerateSignature(hash);
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
