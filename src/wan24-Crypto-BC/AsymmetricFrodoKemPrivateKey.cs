using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEMasymmetric private key
    /// </summary>
    public sealed record class AsymmetricFrodoKemPrivateKey
        : BouncyCastleAsymmetricPrivateKeyExchangeKeyBase<
            AsymmetricFrodoKemPublicKey, 
            AsymmetricFrodoKemAlgorithm, 
            FrodoPublicKeyParameters, 
            FrodoPrivateKeyParameters, 
            FrodoKEMGenerator, 
            FrodoKEMExtractor, 
            AsymmetricFrodoKemPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFrodoKemPrivateKey() : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFrodoKemPrivateKey(byte[] keyData) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricFrodoKemPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys == null) return;
            Keys.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys == null) return;
            Keys.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricFrodoKemPublicKey(AsymmetricFrodoKemPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricFrodoKemPrivateKey(byte[] data) => Import<AsymmetricFrodoKemPrivateKey>(data);
    }
}
