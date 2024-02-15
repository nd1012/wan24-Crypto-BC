using Org.BouncyCastle.Pqc.Crypto.NtruPrime;

//TODO PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo doesn't support SNtruPrimaPrivateKeyParameters !? (waiting for a fix and an update of the NuGet package at present)

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Streamlined NTRU Prime helper
    /// </summary>
    public static class AsymmetricSNtruPrimeHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this SNtruPrimeParameters param)
        {
            if (param == SNtruPrimeParameters.sntrup653) return 653;
            if (param == SNtruPrimeParameters.sntrup761) return 761;
            if (param == SNtruPrimeParameters.sntrup857) return 857;
            if (param == SNtruPrimeParameters.sntrup953) return 953;
            if (param == SNtruPrimeParameters.sntrup1013) return 1013;
            if (param == SNtruPrimeParameters.sntrup1277) return 1277;
            throw new ArgumentException("Invalid Streamlined NTRU Prime parameters", nameof(param));
        }

        /// <summary>
        /// Get the Streamline NTRU Prime parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static SNtruPrimeParameters GetParameters(int keySize) => keySize switch
        {
            653 => SNtruPrimeParameters.sntrup653,
            761 => SNtruPrimeParameters.sntrup761,
            857 => SNtruPrimeParameters.sntrup857,
            953 => SNtruPrimeParameters.sntrup953,
            1013 => SNtruPrimeParameters.sntrup1013,
            1277 => SNtruPrimeParameters.sntrup1277,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
