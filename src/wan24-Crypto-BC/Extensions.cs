using Org.BouncyCastle.Crypto.Prng;
using System.Reflection;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// <see cref="VmpcRandomGenerator"/> type
        /// </summary>
        private static readonly Type VmpcRandomGeneratorType = typeof(VmpcRandomGenerator);

        /// <summary>
        /// Get the internal state (you shouldn't add seed during this method is being executed!)
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <returns>Internal state</returns>
        public static byte[] GetState(this VmpcRandomGenerator rng)
        {
            byte[] p = (byte[])VmpcRandomGeneratorType.GetFieldCached("P", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(rng)!,
                res = new byte[p.Length + 2];
            lock (p)
            {
                p.AsSpan().CopyTo(res);
                p[^2] = (byte)VmpcRandomGeneratorType.GetFieldCached("s", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(rng)!;
                p[^1] = (byte)VmpcRandomGeneratorType.GetFieldCached("n", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(rng)!;
            }
            return res;
        }

        /// <summary>
        /// Restore the internal state (you shouldn't add seed during this method is being executed!)
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <param name="state">Stored internal state</param>
        public static void RestoreState(this VmpcRandomGenerator rng, ReadOnlySpan<byte> state)
        {
            byte[] p = (byte[])VmpcRandomGeneratorType.GetFieldCached("P", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(rng)!;
            if (state.Length < p.Length + 2) throw new ArgumentOutOfRangeException(nameof(state));
            lock (p)
            {
                state[..p.Length].CopyTo(p);
                VmpcRandomGeneratorType.GetFieldCached("s", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(rng, state[p.Length]);
                VmpcRandomGeneratorType.GetFieldCached("n", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(rng, state[p.Length + 1]);
            }
        }
    }
}
