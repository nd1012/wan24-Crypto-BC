using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric private key
    /// </summary>
    public sealed class AsymmetricKyberPrivateKey : AsymmetricPrivateKeyBase<AsymmetricKyberPublicKey, AsymmetricKyberPrivateKey>, IKeyExchangePrivateKey
    {
        /// <summary>
        /// Keys
        /// </summary>
        private AsymmetricCipherKeyPair? Keys = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricKyberPrivateKey() : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricKyberPrivateKey(byte[] keyData) : this() => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricKyberPrivateKey(AsymmetricCipherKeyPair keys) : this()
        {
            Keys = keys;
            KeyData = new(SerializeKeyData());
        }

        /// <summary>
        /// Private key
        /// </summary>
        public KyberPrivateKeyParameters PrivateKey
        {
            get
            {
                if (Keys == null) DeserializeKeyData();
                return (KyberPrivateKeyParameters)Keys!.Private;
            }
        }

        /// <inheritdoc/>
        public override AsymmetricKyberPublicKey PublicKey
        {
            get
            {
                if (Keys == null) throw new InvalidOperationException();
                return _PublicKey ??= new((KyberPublicKeyParameters)Keys.Public);
            }
        }

        /// <inheritdoc/>
        public override int Bits => PublicKey.Bits;

        /// <inheritdoc/>
        public override (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null)
        {
            publicKey ??= options?.PublicKey ?? options?.PrivateKey?.PublicKey ?? PublicKey;
            if (publicKey is not AsymmetricKyberPublicKey key) throw new ArgumentException("Missing valid CRYSTALS-Kyber public key", nameof(publicKey));
            ISecretWithEncapsulation secret = new KyberKemGenerator(new SecureRandom(new BC.RandomGenerator())).GenerateEncapsulated(key.PublicKey);
            return (secret.GetSecret(), secret.GetEncapsulation());
        }

        /// <inheritdoc/>
        public override byte[] DeriveKey(byte[] keyExchangeData) => new KyberKemExtractor(PrivateKey).ExtractSecret(keyExchangeData);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) { }//TODO Clear all keys

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        private byte[] SerializeKeyData()
        {
            if (Keys == null) throw new InvalidOperationException();
            using MemoryStream ms = new();//TODO Use secure memory stream
            ms.WriteNumber(StreamSerializer.VERSION);
            byte[] keyInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((KyberPrivateKeyParameters)Keys.Private).PrivateKeyData.GetEncoded();
            try
            {
                ms.WriteBytes(keyInfo);
                keyInfo.Clear();
                keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((KyberPublicKeyParameters)Keys.Public).GetEncoded();
                ms.WriteBytes(keyInfo);
                keyInfo.Clear();
            }
            catch
            {
                keyInfo.Clear();
                throw;
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        private void DeserializeKeyData()
        {
            using MemoryStream ms = new(KeyData.Array);//TODO Use secure memory stream
            int serializerVersion = ms.ReadNumber<int>();
            if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
            byte[] keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
            try
            {
                KyberPrivateKeyParameters privateKey = (KyberPrivateKeyParameters)PrivateKeyFactory.CreateKey(keyInfo);
                keyInfo.Clear();
                keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                KyberPublicKeyParameters publicKey = (KyberPublicKeyParameters)PublicKeyFactory.CreateKey(keyInfo);
                keyInfo.Clear();
                Keys = new(publicKey, privateKey);
            }
            catch
            {
                keyInfo.Clear();
                throw;
            }
        }
    }
}
