using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XEd448 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricXEd448PublicKey
        : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2<AsymmetricXEd448Algorithm, Ed448PublicKeyParameters, Ed448Signer, AsymmetricXEd448PublicKey>
    {
        /// <summary>
        /// Public X448 key
        /// </summary>
        internal AsymmetricX448PublicKey? _PublicKey2 = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricXEd448PublicKey() : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricXEd448PublicKey(byte[] keyData) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Ed448 public key</param>
        /// <param name="publicKey2">X448 public key</param>
        public AsymmetricXEd448PublicKey(Ed448PublicKeyParameters publicKey, AsymmetricX448PublicKey publicKey2) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME)
        {
            _PublicKey = publicKey;
            _PublicKey2 = publicKey2;
            KeyData = new(SerializeKeyData());
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricXEd448PublicKey(Ed448PublicKeyParameters publicKey) : base(AsymmetricXEd448Algorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return 448;
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
        /// Create a Ed448 public key instance
        /// </summary>
        /// <returns>Ed448 public key (don't forget to dispose!)</returns>
        public AsymmetricEd448PublicKey CreateEd448PublicKey()
            => IfUndisposed(() => new AsymmetricEd448PublicKey(new Ed448PublicKeyParameters(_PublicKey?.GetEncoded() ?? throw new InvalidOperationException())));

        /// <summary>
        /// Create a X448 public key instance
        /// </summary>
        /// <returns>X448 public key (don't forget to dispose!)</returns>
        public AsymmetricX448PublicKey CreateX448PublicKey()
            => IfUndisposed(() => _PublicKey2?.GetCopy() as AsymmetricX448PublicKey ?? throw new InvalidOperationException());

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
        public static explicit operator AsymmetricXEd448PublicKey(byte[] data) => Import<AsymmetricXEd448PublicKey>(data);
    }
}
