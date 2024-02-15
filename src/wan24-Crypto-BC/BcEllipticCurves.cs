using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle elliptic curves
    /// </summary>
    public static class BcEllipticCurves
    {
        /// <summary>
        /// secp256r1 curve (NIST P-256, 128 bit security)
        /// </summary>
        public static readonly ECDomainParameters SECP256R1_CURVE = new(SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1));
        /// <summary>
        /// secp384r1 curve (NIST P-384, 192 bit security)
        /// </summary>
        public static readonly ECDomainParameters SECP384R1_CURVE = new(SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1));
        /// <summary>
        /// secp521r1 curve (NIST P-521, 260 bit security)
        /// </summary>
        public static readonly ECDomainParameters SECP521R1_CURVE = new(SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1));

        /// <summary>
        /// Get the key size for a curve
        /// </summary>
        /// <param name="curve">Curve name</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(ECDomainParameters curve)
        {
            if (curve.Equals(SECP256R1_CURVE)) return EllipticCurves.SECP256R1_KEY_SIZE;
            if (curve.Equals(SECP384R1_CURVE)) return EllipticCurves.SECP384R1_KEY_SIZE;
            if (curve.Equals(SECP521R1_CURVE)) return EllipticCurves.SECP521R1_KEY_SIZE;
            throw new ArgumentException("Unknown curve", nameof(curve));
        }

        /// <summary>
        /// Get the curve from a key size
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        /// <returns>Curve name</returns>
        public static ECDomainParameters GetCurve(int bits) => bits switch
        {
            EllipticCurves.SECP256R1_KEY_SIZE => SECP256R1_CURVE,
            EllipticCurves.SECP384R1_KEY_SIZE => SECP384R1_CURVE,
            EllipticCurves.SECP521R1_KEY_SIZE => SECP521R1_CURVE,
            _ => throw new ArgumentException("Unknown key size", nameof(bits))
        };
    }
}
