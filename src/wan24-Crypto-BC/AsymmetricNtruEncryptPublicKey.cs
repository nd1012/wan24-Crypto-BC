using Org.BouncyCastle.Pqc.Crypto.Ntru;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// NTRUEncrypt asymmetric public key
    /// </summary>
    public sealed record class AsymmetricNtruEncryptPublicKey
        : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricNtruEncryptAlgorithm, NtruPublicKeyParameters, AsymmetricNtruEncryptPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricNtruEncryptPublicKey() : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricNtruEncryptPublicKey(byte[] keyData) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricNtruEncryptPublicKey(NtruPublicKeyParameters publicKey) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return _PublicKey?.Parameters.GetKeySize() ?? throw new InvalidOperationException();
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

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (_PublicKey == null) throw new InvalidOperationException();
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                using SecureByteArray publicKey = new(_PublicKey.PublicKey);
                ms.WriteSerializerVersion()
                    .WriteNumber(Bits)
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
                using MemoryStream ms = new(KeyData.Array);
                int ssv = ms.ReadSerializerVersion();
                NtruParameters param = AsymmetricNtruHelper.GetParameters(ms.ReadNumber<int>(ssv));
                _PublicKey = new(param, ms.ReadBytes(ssv, minLen: 1, maxLen: ushort.MaxValue).Value);
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
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricNtruEncryptPublicKey(byte[] data) => Import<AsymmetricNtruEncryptPublicKey>(data);
    }
}
