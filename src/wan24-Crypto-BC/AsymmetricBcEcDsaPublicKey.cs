using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric EC DSA public key
    /// </summary>
    public sealed record class AsymmetricBcEcDsaPublicKey
        : BouncyCastleAsymmetricNonPqcPublicKeyBase<AsymmetricBcEcDsaAlgorithm, ECPublicKeyParameters, AsymmetricBcEcDsaPublicKey>, ISignaturePublicKey
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBcEcDsaPublicKey() : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBcEcDsaPublicKey(byte[] keyData) : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricBcEcDsaPublicKey(ECPublicKeyParameters publicKey) : base(AsymmetricBcEcDsaAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is null) throw new InvalidOperationException();
                    return BcEllipticCurves.GetKeySize(_PublicKey.Parameters);
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
        public override bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                DsaDigestSigner signer = new(new ECDsaSigner(), new NullDigest());
                signer.Init(forSigning: false, PublicKey);
                signer.BlockUpdate(signedHash);
                bool res = signer.VerifySignature(signature);
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
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricBcEcDsaPublicKey(byte[] data) => Import<AsymmetricBcEcDsaPublicKey>(data);
    }
}
