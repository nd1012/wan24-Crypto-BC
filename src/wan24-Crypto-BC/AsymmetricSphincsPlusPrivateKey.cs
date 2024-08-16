using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using System.Reflection;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric private key
    /// </summary>
    public sealed record class AsymmetricSphincsPlusPrivateKey
        : BouncyCastleAsymmetricPqcPrivateSignatureKeyBase<
            AsymmetricSphincsPlusPublicKey, 
            AsymmetricSphincsPlusAlgorithm, 
            SphincsPlusPublicKeyParameters, 
            SphincsPlusPrivateKeyParameters, 
            SphincsPlusSigner, 
            AsymmetricSphincsPlusPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusPrivateKey() : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSphincsPlusPrivateKey(byte[] keyData) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricSphincsPlusPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keys) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public AsymmetricSphincsPlusPrivateKey(SphincsPlusPrivateKeyParameters privateKey) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, privateKey) { }

        /// <inheritdoc/>
        protected override SphincsPlusPublicKeyParameters GetPublicKey(SphincsPlusPrivateKeyParameters privateKey) => new(privateKey.Parameters, privateKey.GetPublicKey());

        /// <inheritdoc/>
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
                using SecureByteArray privateKey = new((Keys.Private as SphincsPlusPrivateKeyParameters)!.GetEncoded());
                using SecureByteArray publicKey = new((Keys.Public as SphincsPlusPublicKeyParameters)!.GetEncoded());
                ms.WriteSerializerVersion()
                    .WriteNumber(Bits)
                    .WriteBytes(privateKey.Array)
                    //TODO Don't include SPHINCS+ public key in serialized data
                    .WriteBytes(publicKey.Array);
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
        protected override void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                SphincsPlusPrivateKeyParameters? privateKey = null;
                SphincsPlusPublicKeyParameters? publicKey = null;
                try
                {
                    using MemoryStream ms = new(KeyData.Array);
                    int ssv = ms.ReadSerializerVersion();
                    SphincsPlusParameters param = AsymmetricSphincsPlusHelper.GetParameters(ms.ReadNumber<int>(ssv));
                    using SecureByteArrayRefStruct privateKeyInfo = new(ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
                    privateKey = new(param, privateKeyInfo.Array);
                    publicKey = new(param, ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
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
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys is null) return;
            //TODO All parameter fields are private :(
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_sk", BindingFlags.Instance | BindingFlags.NonPublic)!.Getter!(Keys.Private)!.ClearPrivateByteArrayFields();
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_pk", BindingFlags.Instance | BindingFlags.NonPublic)!.Getter!(Keys.Private)!.ClearPrivateByteArrayFields();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys is null) return;
            //TODO All parameter fields are private :(
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_sk", BindingFlags.Instance | BindingFlags.NonPublic)!.Getter!(Keys.Private)!.ClearPrivateByteArrayFields();
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_pk", BindingFlags.Instance | BindingFlags.NonPublic)!.Getter!(Keys.Private)!.ClearPrivateByteArrayFields();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricSphincsPlusPublicKey(AsymmetricSphincsPlusPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricSphincsPlusPrivateKey(byte[] data) => Import<AsymmetricSphincsPlusPrivateKey>(data);
    }
}
