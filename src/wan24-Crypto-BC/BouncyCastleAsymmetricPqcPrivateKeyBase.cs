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

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="privateKey">Private key</param>
        protected BouncyCastleAsymmetricPqcPrivateKeyBase(string algorithm, tPrivateKey privateKey) : base(algorithm, privateKey) { }

        /// <inheritdoc/>
        public override byte[] ExportBc()
        {
            try
            {
                EnsureUndisposed();
                if (Keys is null) throw new InvalidOperationException();
                return PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private).GetDerEncoded();
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
                if (Keys == null) throw new InvalidOperationException();
                return PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private).GetDerEncoded();
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
                tPrivateKey? privateKey = null;
                tPublicKey? publicKey = null;
                try
                {
                    privateKey = (tPrivateKey)PqcPrivateKeyFactory.CreateKey(KeyData.Array);
                    publicKey = GetPublicKey(privateKey);
                    Keys = new(publicKey, privateKey);
                }
                catch
                {
                    privateKey?.ClearPrivateByteArrayFields();
                    publicKey?.ClearPrivateByteArrayFields();
                    throw;
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

        /// <inheritdoc/>
        protected override byte[] SerializeFullKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (Keys is null) throw new InvalidOperationException();
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                using SecureByteArrayRefStruct privateKey = new(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private).GetDerEncoded());
                using SecureByteArrayRefStruct publicKey = new(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Keys.Public).GetDerEncoded());
                ms.WriteSerializerVersion()
                    .WriteBytes(privateKey)
                    .WriteBytes(publicKey);
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

        /// <inheritdoc/>
        protected override void DeserializeFullKeyData()
        {
            try
            {
                EnsureUndisposed();
                tPrivateKey? privateKey = null;
                tPublicKey? publicKey = null;
                try
                {
                    using MemoryStream ms = new(KeyData.Array);
                    int ssv = ms.ReadSerializerVersion();
                    using SecureByteArrayRefStruct privateKeyInfo = new(ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
                    using SecureByteArrayRefStruct publicKeyInfo = new(ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
                    privateKey = (tPrivateKey)PqcPrivateKeyFactory.CreateKey(privateKeyInfo);
                    publicKey = (tPublicKey)PqcPublicKeyFactory.CreateKey(publicKeyInfo);
                    Keys = new(publicKey, privateKey);
                }
                catch
                {
                    privateKey?.ClearPrivateByteArrayFields();
                    publicKey?.ClearPrivateByteArrayFields();
                    throw;
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

        /// <inheritdoc/>
        new public static tFinal ImportBc(in byte[] keyInfo)
        {
            try
            {
                return (tFinal)(Activator.CreateInstance(typeof(tFinal), PqcPrivateKeyFactory.CreateKey(keyInfo) as tPrivateKey
                    ?? throw new InvalidDataException($"Failed to deserialize {typeof(tPrivateKey)} from the given key data"))
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}"));
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
