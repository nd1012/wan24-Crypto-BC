using Org.BouncyCastle.Pqc.Crypto.Frodo;

//TODO Use FalconKEM Shake parameter sets in newer version, use key complexity instead of session key size in bits as "key size"

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEM helper
    /// </summary>
    public static class AsymmetricFrodoKemHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this FrodoParameters param)
        {
            if (param == FrodoParameters.frodokem640aes) return 128;
            if (param == FrodoParameters.frodokem976aes) return 192;
            if (param == FrodoParameters.frodokem1344aes) return 256;
            throw new ArgumentException("Invalid FrodoKEM parameters", nameof(param));
        }

        /// <summary>
        /// Get the FrodoKEM parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static FrodoParameters GetParameters(int keySize) => keySize switch
        {
            128 => FrodoParameters.frodokem640aes,
            192 => FrodoParameters.frodokem976aes,
            256 => FrodoParameters.frodokem1344aes,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
