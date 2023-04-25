using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric public key
    /// </summary>
    public sealed class AsymmetricKyberPublicKey : AsymmetricPublicKeyBase
    {
        /// <summary>
        /// Public key
        /// </summary>
        private KyberPublicKeyParameters? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricKyberPublicKey() : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricKyberPublicKey(byte[] keyData) : this() => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricKyberPublicKey(KyberPublicKeyParameters publicKey) : this()
        {
            _PublicKey = publicKey;
            KeyData = new(SerializeKeyData());
        }

        /// <summary>
        /// Public key
        /// </summary>
        public KyberPublicKeyParameters PublicKey
        {
            get
            {
                if (_PublicKey == null) DeserializeKeyData();
                return _PublicKey!;
            }
        }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                EnsureUndisposed();
                return _PublicKey?.Parameters.GetKeySize() ?? throw new InvalidOperationException();
            }
        }

        /// <inheritdoc/>
        public override IAsymmetricPublicKey GetCopy()
        {
            EnsureUndisposed();
            return new AsymmetricKyberPublicKey((byte[])KeyData.Array.Clone());
        }

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        private byte[] SerializeKeyData()
        {
            using MemoryStream ms = new();
            ms.WriteNumber(StreamSerializer.VERSION);
            ms.WriteBytes(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded());
            return ms.ToArray();
        }

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        private void DeserializeKeyData()
        {
            using MemoryStream ms = new(KeyData.Array);
            int serializerVersion = ms.ReadNumber<int>();
            if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
            _PublicKey = (KyberPublicKeyParameters)PqcPublicKeyFactory.CreateKey(ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value);
        }
    }
}
