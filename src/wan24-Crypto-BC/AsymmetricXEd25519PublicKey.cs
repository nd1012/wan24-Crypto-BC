using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XEd25519 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricXEd25519PublicKey
        : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase<AsymmetricXEd25519Algorithm, Ed25519PublicKeyParameters, Ed25519Signer, AsymmetricXEd25519PublicKey>
    {
        /// <summary>
        /// Public X25519 key
        /// </summary>
        internal AsymmetricX25519PublicKey? _PublicKey2 = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricXEd25519PublicKey() : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricXEd25519PublicKey(byte[] keyData) : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Ed25519 public key parameters</param>
        /// <param name="publicKey2">X25519 public key</param>
        public AsymmetricXEd25519PublicKey(Ed25519PublicKeyParameters publicKey, AsymmetricX25519PublicKey publicKey2) : base(AsymmetricXEd25519Algorithm.ALGORITHM_NAME)
        {
            _PublicKey = publicKey;
            _PublicKey2 = publicKey2;
            KeyData = new(SerializeKeyData());
        }

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
                    return 256;
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
        /// Create a Ed25519 public key instance
        /// </summary>
        /// <returns>Ed25519 public key (don't forget to dispose!)</returns>
        public AsymmetricEd25519PublicKey CreateEd25519PublicKey()
            => IfUndisposed(() => new AsymmetricEd25519PublicKey(new Ed25519PublicKeyParameters(_PublicKey?.GetEncoded() ?? throw new InvalidOperationException())));

        /// <summary>
        /// Create a X25519 public key instance
        /// </summary>
        /// <returns>X25519 public key (don't forget to dispose!)</returns>
        public AsymmetricX25519PublicKey CreateX25519PublicKey()
            => IfUndisposed(() => _PublicKey2?.GetCopy() as AsymmetricX25519PublicKey ?? throw new InvalidOperationException());

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (_PublicKey is null || _PublicKey2 is null) throw new InvalidOperationException();
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                using SecureByteArrayRefStruct publicKey = new(_PublicKey.GetEncoded());
                ms.WriteSerializerVersion()
                    .WriteBytes(publicKey.Array)
                    .WriteBytes(_PublicKey2.KeyData.Array);
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
                _PublicKey = new(ms.ReadBytes(ssv, minLen: 1, maxLen: ushort.MaxValue).Value);
                _PublicKey2 = new(ms.ReadBytes(ssv, minLen: 1, maxLen: ushort.MaxValue).Value);
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
            _PublicKey2?.Dispose();
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _PublicKey2?.Dispose();
            return base.DisposeCore();
        }

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricXEd25519PublicKey(byte[] data) => Import<AsymmetricXEd25519PublicKey>(data);
    }
}
