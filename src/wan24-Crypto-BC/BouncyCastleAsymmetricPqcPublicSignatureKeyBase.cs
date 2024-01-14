using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric PQC public signature key
    /// </summary>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tSigner">Signer type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricPqcPublicSignatureKeyBase<tAlgo, tPublicKey, tSigner, tFinal>
        : BouncyCastleAsymmetricPqcPublicKeyBase<tAlgo, tPublicKey, tFinal>, ISignaturePublicKey
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tSigner : class, IMessageSigner, new()
        where tFinal : BouncyCastleAsymmetricPqcPublicSignatureKeyBase<tAlgo, tPublicKey, tSigner, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected BouncyCastleAsymmetricPqcPublicSignatureKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPqcPublicSignatureKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="publicKey">Public key</param>
        protected BouncyCastleAsymmetricPqcPublicSignatureKeyBase(string algorithm, tPublicKey publicKey) : base(algorithm, publicKey) { }

        /// <inheritdoc/>
        public sealed override bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                tSigner signer = new();
                signer.Init(forSigning: false, PublicKey);
                bool res = signer.VerifySignature(signedHash, signature);
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
                return res;
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

        /// <inheritdoc/>
        protected sealed override bool ValidateSignatureInt(SignatureContainer signature, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                bool res = ValidateSignatureRaw(signature.Signature, signature.CreateSignatureHash());
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
                return res;
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
}
