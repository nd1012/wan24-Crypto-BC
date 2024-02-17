using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class fo a Bouncy Castle asymmetric PQC public key
    /// </summary>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricPqcPublicKeyBase<tAlgo, tPublicKey, tFinal> : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tFinal>
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tFinal : BouncyCastleAsymmetricPqcPublicKeyBase<tAlgo, tPublicKey, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPqcPublicKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPqcPublicKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="publicKey">Public key</param>
        protected BouncyCastleAsymmetricPqcPublicKeyBase(string algorithm, tPublicKey publicKey) : base(algorithm, publicKey) { }

        /// <inheritdoc/>
        public override byte[] ExportBc()
        {
            try
            {
                EnsureUndisposed();
                if (_PublicKey is null) throw new InvalidOperationException();
                return PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetDerEncoded();
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (_PublicKey == null) throw new InvalidOperationException();
                return PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetDerEncoded();
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
        protected override void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                _PublicKey = (tPublicKey)PqcPublicKeyFactory.CreateKey(KeyData.Array);
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
        new public static tFinal ImportBc(in byte[] keyInfo)
        {
            try
            {
                return (tFinal)(Activator.CreateInstance(typeof(tFinal), PqcPublicKeyFactory.CreateKey(keyInfo) as tPublicKey
                    ?? throw new InvalidDataException())
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}"));
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
