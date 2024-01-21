using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using System.Reflection;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric private key
    /// </summary>
    public sealed record class AsymmetricSphincsPlusPrivateKey
        : BouncyCastleAsymmetricPqcPrivateSignatureKeyBase<
            AsymmetricSphincsPlusPublicKey, 
            AsymmetricSphincsPlusAlgorithm, 
            SphincsPlusPublicKeyParameters, 
            SphincsPlusPrivateKeyParameters, 
            SphincsPlusSigner, 
            AsymmetricSphincsPlusPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusPrivateKey() : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSphincsPlusPrivateKey(byte[] keyData) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricSphincsPlusPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        protected override SphincsPlusPublicKeyParameters GetPublicKey(SphincsPlusPrivateKeyParameters privateKey) => new(privateKey.Parameters, privateKey.GetPublicKey());

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Keys is null) return;
            //TODO All parameter fields are private :(
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_sk", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Keys.Private)!.ClearPrivateByteArrayFields();
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_pk", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Keys.Private)!.ClearPrivateByteArrayFields();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (Keys is null) return;
            //TODO All parameter fields are private :(
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_sk", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Keys.Private)!.ClearPrivateByteArrayFields();
            typeof(SphincsPlusPrivateKeyParameters).GetFieldCached("m_pk", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(Keys.Private)!.ClearPrivateByteArrayFields();
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricSphincsPlusPublicKey(AsymmetricSphincsPlusPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricSphincsPlusPrivateKey(byte[] data) => Import<AsymmetricSphincsPlusPrivateKey>(data);
    }
}
