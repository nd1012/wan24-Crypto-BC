using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class fo a Bouncy Castle asymmetric public key
    /// </summary>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tFinal> : AsymmetricPublicKeyBase
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tFinal : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tFinal>, new()
    {
        /// <summary>
        /// Public key
        /// </summary>
        protected tPublicKey? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm, byte[] keyData) : this(algorithm)
        {
            KeyData = new(keyData);
            DeserializeKeyData();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="publicKey">Public key</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm, tPublicKey publicKey) : this(algorithm)
        {
            try
            {
                _PublicKey = publicKey;
                KeyData = new(SerializeKeyData());
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

        /// <summary>
        /// Is the key info export/import implemented in the Bouncy Castle library AND <c>wan24-Crypto-BC</c>?
        /// </summary>
        public static bool IsBcImportExportImplemented { get; } = true;

        /// <summary>
        /// Public key
        /// </summary>
        public tPublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is null) DeserializeKeyData();
                    return _PublicKey!;
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
        /// Export the key in Bouncy Castle format, if possible
        /// </summary>
        /// <returns>Serialized key data (DER encoded; don't forget to clear!)</returns>
        public virtual byte[] ExportBc()
        {
            try
            {
                EnsureUndisposed();
                if (!IsBcImportExportImplemented) throw new NotSupportedException();
                if (_PublicKey is null) throw new InvalidOperationException();
                return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetDerEncoded();
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public sealed override IAsymmetricPublicKey GetCopy()
        {
            try
            {
                EnsureUndisposed();
                return Activator.CreateInstance(typeof(tFinal), KeyData.Array.CloneArray()) as IAsymmetricPublicKey
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}");
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        protected abstract byte[] SerializeKeyData();

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        protected abstract void DeserializeKeyData();

        /// <summary>
        /// Import a key in Bouncy Castle format (created by <see cref="ExportBc"/>)
        /// </summary>
        /// <param name="keyInfo">Serialized key data (created by <see cref="ExportBc"/>; won't be cleared)</param>
        /// <returns>Key (don't forget to dispose!)</returns>
        public static tFinal ImportBc(in byte[] keyInfo)
        {
            try
            {
                if (!IsBcImportExportImplemented) throw new NotSupportedException();
                return (tFinal)(Activator.CreateInstance(typeof(tFinal), PublicKeyFactory.CreateKey(keyInfo) as tPublicKey
                    ?? throw new InvalidDataException())
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}"));
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
