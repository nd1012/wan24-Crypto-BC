using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric FALCON private key
    /// </summary>
    public sealed record class AsymmetricFalconPrivateKey
        : BouncyCastleAsymmetricPqcPrivateSignatureKeyBase<
            AsymmetricFalconPublicKey, 
            AsymmetricFalconAlgorithm, 
            FalconPublicKeyParameters, 
            FalconPrivateKeyParameters, 
            FalconSigner, 
            AsymmetricFalconPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFalconPrivateKey() : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFalconPrivateKey(byte[] keyData) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricFalconPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        protected override FalconPublicKeyParameters GetPublicKey(FalconPrivateKeyParameters privateKey) => new(privateKey.Parameters, privateKey.GetPublicKey());

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
        public static implicit operator AsymmetricFalconPublicKey(AsymmetricFalconPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricFalconPrivateKey(byte[] data) => Import<AsymmetricFalconPrivateKey>(data);
    }
}
