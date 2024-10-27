using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Streamlined NTRU Prime asymmetric private key
    /// </summary>
    public sealed record class AsymmetricSNtruPrimePrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
            AsymmetricSNtruPrimePublicKey,
            AsymmetricSNtruPrimeAlgorithm,
            SNtruPrimePublicKeyParameters,
            SNtruPrimePrivateKeyParameters,
            SNtruPrimeKemGenerator,
            SNtruPrimeKemExtractor,
            AsymmetricSNtruPrimePrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSNtruPrimePrivateKey() : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSNtruPrimePrivateKey(byte[] keyData) : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricSNtruPrimePrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricSNtruPrimeAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

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
                using SecureByteArray privateKey = new((Keys.Private as SNtruPrimePrivateKeyParameters)!.GetPrivateKey());
                using SecureByteArray publicKey = new((Keys.Public as SNtruPrimePublicKeyParameters)!.GetPublicKey());
                ms.WriteSerializerVersion()
                    .WriteNumber(Bits)
                    .WriteBytes(privateKey.Array)
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
                SNtruPrimePrivateKeyParameters? privateKey = null;
                SNtruPrimePublicKeyParameters? publicKey = null;
                try
                {
                    using MemoryStream ms = new(KeyData.Array);
                    int ssv = ms.ReadSerializerVersion();
                    SNtruPrimeParameters param = AsymmetricSNtruPrimeHelper.GetParameters(ms.ReadNumber<int>(ssv));
                    using RentedMemoryRef<byte> buffer = new(len: ushort.MaxValue, clean: false)
                    {
                        Clear = true
                    };
                    Memory<byte> bufferMem = buffer.Memory;
                    Span<byte> bufferSpan = bufferMem.Span;
                    int red = ms.ReadBytes(bufferMem, ssv, maxLen: ushort.MaxValue);
                    privateKey = new(param, bufferSpan[..red].ToArray());
                    red = ms.ReadBytes(bufferMem, ssv, maxLen: ushort.MaxValue);
                    publicKey = new(param, bufferSpan[..red].ToArray());
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
        protected override SNtruPrimePublicKeyParameters GetPublicKey(SNtruPrimePrivateKeyParameters privateKey) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricSNtruPrimePublicKey(AsymmetricSNtruPrimePrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricSNtruPrimePrivateKey(byte[] data) => Import<AsymmetricSNtruPrimePrivateKey>(data);
    }
}
