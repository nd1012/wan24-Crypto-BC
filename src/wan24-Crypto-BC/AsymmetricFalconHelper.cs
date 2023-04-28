using Org.BouncyCastle.Pqc.Crypto.Falcon;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric FALCON algorithm helper
    /// </summary>
    public static class AsymmetricFalconHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this FalconParameters param)
        {
            if (param == FalconParameters.falcon_512) return 512;
            if (param == FalconParameters.falcon_1024) return 1024;
            throw new ArgumentException("Invalid FALCON parameters", nameof(param));
        }

        /// <summary>
        /// Get the CRYSTALS-Kyber parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static FalconParameters GetParameters(int keySize) => keySize switch
        {
            512 => FalconParameters.falcon_512,
            1024 => FalconParameters.falcon_1024,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
