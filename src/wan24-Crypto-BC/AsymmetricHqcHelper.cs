using Org.BouncyCastle.Pqc.Crypto.Hqc;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HQC asymmetric algorithm helper
    /// </summary>
    public static class AsymmetricHqcHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this HqcParameters param)
        {
            if (param == HqcParameters.hqc128) return 128;
            if (param == HqcParameters.hqc192) return 192;
            if (param == HqcParameters.hqc256) return 256;
            throw new ArgumentException("Invalid HQC parameters", nameof(param));
        }

        /// <summary>
        /// Get the HQC parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static HqcParameters GetParameters(int keySize) => keySize switch
        {
            128 => HqcParameters.hqc128,
            192 => HqcParameters.hqc192,
            256 => HqcParameters.hqc256,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
