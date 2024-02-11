using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric algorithm helper
    /// </summary>
    public static class AsymmetricSphincsPlusHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this SphincsPlusParameters param)
        {
            if (param == SphincsPlusParameters.haraka_128f_simple) return 128;
            if (param == SphincsPlusParameters.haraka_192f_simple) return 192;
            if (param == SphincsPlusParameters.haraka_256f_simple) return 256;
            throw new ArgumentException("Invalid SPHINCS+ parameters", nameof(param));
        }

        /// <summary>
        /// Get the SPHINCS+ parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static SphincsPlusParameters GetParameters(int keySize) => keySize switch
        {
            128 => SphincsPlusParameters.haraka_128f_simple,
            192 => SphincsPlusParameters.haraka_192f_simple,
            256 => SphincsPlusParameters.haraka_256f_simple,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
