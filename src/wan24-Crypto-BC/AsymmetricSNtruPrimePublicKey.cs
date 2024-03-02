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
                ms.Write(Bits);
                ms.Write(publicKey.Length);
                ms.Write(publicKey.Span);
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
                SNtruPrimeParameters param = AsymmetricSNtruPrimeHelper.GetParameters(ms.ReadInt());
                int len = ms.ReadInt();
                if (len < 1 || len > MaxArrayLength) throw new InvalidDataException($"Invalid key length {len}");
                byte[] buffer = new byte[len];
                ms.ReadExactly(buffer);
                _PublicKey = new(param, buffer);
                if (ms.Length != ms.Position) throw new InvalidDataException("Didn't use all key data");
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
