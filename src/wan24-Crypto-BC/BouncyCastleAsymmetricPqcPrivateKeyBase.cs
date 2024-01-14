using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric PQC private key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tPrivateKey">Internal private key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricPqcPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal> : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>
        where tPublic : BouncyCastleAsymmetricPqcPublicKeyBase<tAlgo, tPublicKey, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey: AsymmetricKeyParameter
        where tFinal : BouncyCastleAsymmetricPqcPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPqcPrivateKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPqcPrivateKeyBase(string algorithm, byte[] keyData) : base(algorithm, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricPqcPrivateKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : base(algorithm, keys) { }

        /// <inheritdoc/>>
        protected override byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (Keys == null) throw new InvalidOperationException();
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                ms.WriteNumber(StreamSerializer.VERSION);
                byte[] keyInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private).PrivateKeyData.GetEncoded();
                try
                {
                    ms.WriteBytes(keyInfo);
                    keyInfo.Clear();
                    keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Keys.Public).GetEncoded();
                    ms.WriteBytes(keyInfo);
                    keyInfo.Clear();
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
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                ms.Write(KeyData.Array);
                ms.Position = 0;
                int serializerVersion = ms.ReadNumber<int>();
                if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
                byte[] keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                try
                {
                    tPrivateKey privateKey = (tPrivateKey)PqcPrivateKeyFactory.CreateKey(keyInfo);
                    keyInfo.Clear();
                    keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                    tPublicKey publicKey = (tPublicKey)PqcPublicKeyFactory.CreateKey(keyInfo);
                    keyInfo.Clear();
                    Keys = new(publicKey, privateKey);
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
