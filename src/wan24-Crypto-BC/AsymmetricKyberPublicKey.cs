﻿using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;
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
            try
            {
                _PublicKey = publicKey;
                KeyData = new(SerializeKeyData());
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Public key
        /// </summary>
        public KyberPublicKeyParameters PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey == null) DeserializeKeyData();
                    return _PublicKey!;
                }
                catch (CryptographicException)
                {
                    throw;
                }
                catch(Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

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
        public override IAsymmetricPublicKey GetCopy()
        {
            try
            {
                EnsureUndisposed();
                return new AsymmetricKyberPublicKey((byte[])KeyData.Array.Clone());
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
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        private byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                using MemoryStream ms = new();
                ms.WriteNumber(StreamSerializer.VERSION);
                byte[] keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded();
                try
                {
                    ms.WriteBytes(keyInfo);
                }
                catch(Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
                }
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

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        private void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                using MemoryStream ms = new(KeyData.Array);
                int serializerVersion = ms.ReadNumber<int>();
                if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
                _PublicKey = (KyberPublicKeyParameters)PqcPublicKeyFactory.CreateKey(ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value);
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
}
