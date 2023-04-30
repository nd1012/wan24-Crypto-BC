using Org.BouncyCastle.Pqc.Crypto.Frodo;

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
            if (param == FrodoParameters.frodokem19888r3) return 128;
            if (param == FrodoParameters.frodokem31296r3) return 192;
            if (param == FrodoParameters.frodokem43088r3) return 256;
            throw new ArgumentException("Invalid FrodoKEM parameters", nameof(param));
        }

        /// <summary>
        /// Get the FrodoKEM parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static FrodoParameters GetParameters(int keySize) => keySize switch
        {
            128 => FrodoParameters.frodokem19888r3,
            192 => FrodoParameters.frodokem31296r3,
            256 => FrodoParameters.frodokem43088r3,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
