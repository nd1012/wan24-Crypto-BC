using Org.BouncyCastle.Crypto;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric non-PQC public signature key (which requires a context constructor parameter)
    /// </summary>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tSigner">Signer type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2<tAlgo, tPublicKey, tSigner, tFinal>
        : BouncyCastleAsymmetricNonPqcPublicKeyBase<tAlgo, tPublicKey, tFinal>, ISignaturePublicKey
        where tAlgo : IAsymmetricAlgorithm
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tSigner : class, ISigner
        where tFinal : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2<tAlgo, tPublicKey, tSigner, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="publicKey">Public key</param>
        protected BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2(string algorithm, tPublicKey publicKey) : base(algorithm, publicKey) { }

        /// <inheritdoc/>
        public sealed override bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                tSigner signer = Activator.CreateInstance(typeof(tSigner), Array.Empty<byte>()) as tSigner
                    ?? throw CryptographicException.From(new InvalidProgramException($"Failed to instance {typeof(tSigner)}"));
                signer.Init(forSigning: false, PublicKey);
                signer.BlockUpdate(signedHash);
                bool res = signer.VerifySignature(signature);
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
