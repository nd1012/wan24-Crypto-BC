using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Streamlined NTRU Prime asymmetric public key
    /// </summary>
    public sealed record class AsymmetricSNtruPrimePublicKey
        : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricSNtruPrimeAlgorithm, SNtruPrimePublicKeyParameters, AsymmetricSNtruPrimePublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSNtruPrimePublicKey() : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSNtruPrimePublicKey(byte[] keyData) : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricSNtruPrimePublicKey(SNtruPrimePublicKeyParameters publicKey) : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is null) throw new InvalidOperationException();
                    return AsymmetricSNtruPrimeHelper.GetKeySize(_PublicKey.Parameters);
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
                using SecureByteArray publicKey = new(_PublicKey.GetPublicKey());
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
                SNtruPrimeParameters param = AsymmetricSNtruPrimeHelper.GetParameters(ms.ReadNumber<int>(ssv));
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
        public static explicit operator AsymmetricSNtruPrimePublicKey(byte[] data) => Import<AsymmetricSNtruPrimePublicKey>(data);
    }
}
