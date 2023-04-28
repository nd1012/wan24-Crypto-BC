using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHiNCS+ asymmetric algorithm helper
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
            if (param == SphincsPlusParameters.haraka_128f) return 128;
            if (param == SphincsPlusParameters.haraka_192f) return 192;
            if (param == SphincsPlusParameters.haraka_256f) return 256;
            throw new ArgumentException("Invalid FALCON parameters", nameof(param));
        }

        /// <summary>
        /// Get the SPHINCS+ parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static SphincsPlusParameters GetParameters(int keySize) => keySize switch
        {
            128 => SphincsPlusParameters.haraka_128f,
            192 => SphincsPlusParameters.haraka_192f,
            256 => SphincsPlusParameters.haraka_256f,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
