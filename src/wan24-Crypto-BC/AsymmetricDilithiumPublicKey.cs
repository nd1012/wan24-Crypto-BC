﻿using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric public key
    /// </summary>
    public sealed class AsymmetricDilithiumPublicKey : AsymmetricPublicKeyBase, ISignaturePublicKey
    {
        /// <summary>
        /// Public key
        /// </summary>
        private DilithiumPublicKeyParameters? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricDilithiumPublicKey() : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricDilithiumPublicKey(byte[] keyData) : this() => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricDilithiumPublicKey(DilithiumPublicKeyParameters publicKey) : this()
        {
            try
            {
                _PublicKey = publicKey;
                KeyData = new(SerializeKeyData());
            }
            catch(CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Public key
        /// </summary>
        public DilithiumPublicKeyParameters PublicKey
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
                catch (Exception ex)
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
                return new AsymmetricDilithiumPublicKey((byte[])KeyData.Array.Clone());
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                DilithiumSigner signer = new();
                signer.Init(forSigning: false, PublicKey);
                bool res = signer.VerifySignature(signedHash, signature);
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
                return res;
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
        protected override bool ValidateSignatureInt(SignatureContainer signature, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                bool res = ValidateSignatureRaw(signature.Signature, signature.CreateSignatureHash());
                if (!res && throwOnError) throw new InvalidDataException("Signature validation failed");
                return res;
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
                byte[] keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded();
                try
                {
                    ms.WriteNumber(StreamSerializer.VERSION);
                    ms.WriteBytes(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_PublicKey).GetEncoded());
                }
                catch (Exception ex)
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
            catch(Exception ex)
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
                byte[] keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                try
                {
                    _PublicKey = (DilithiumPublicKeyParameters)PqcPublicKeyFactory.CreateKey(keyInfo);
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
                }
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
}
