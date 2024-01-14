using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;
using wan24.StreamSerializerExtensions;

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

        /// <inheritdoc/>>
        protected override byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                using MemoryStream ms = new();
                byte[] keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded();
                try
                {
                    ms.WriteNumber(StreamSerializer.VERSION);
                    ms.WriteBytes(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded());
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
                }
                return ms.ToArray();
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

        /// <inheritdoc/>>
        protected override void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                using MemoryStream ms = new(KeyData.Array);
                int serializerVersion = ms.ReadNumber<int>();
                if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
                byte[] keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                try
                {
                    _PublicKey = (tPublicKey)PqcPublicKeyFactory.CreateKey(keyInfo);
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
                }
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
