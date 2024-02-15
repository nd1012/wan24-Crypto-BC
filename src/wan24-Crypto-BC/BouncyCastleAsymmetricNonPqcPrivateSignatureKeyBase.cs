using Org.BouncyCastle.Crypto;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric non-PQC private signature key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tPrivateKey">Internal private key type</typeparam>
    /// <typeparam name="tSigner">Signer type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tSigner, tFinal>
        : BouncyCastleAsymmetricNonPqcPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>, ISignaturePrivateKey
        where tPublic : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase<tAlgo, tPublicKey, tSigner, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
        where tSigner : class, ISigner, new()
        where tFinal : BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tSigner, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : base(algorithm, keys) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="privateKey">Private key</param>
        protected BouncyCastleAsymmetricNonPqcPrivateSignatureKeyBase(string algorithm, tPrivateKey privateKey) : base(algorithm, privateKey) { }

        /// <inheritdoc/>
        public override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                EnsureUndisposed();
                tSigner signer = new();
                signer.Init(forSigning: true, PrivateKey);
                signer.BlockUpdate(hash);
                return signer.GenerateSignature();
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
