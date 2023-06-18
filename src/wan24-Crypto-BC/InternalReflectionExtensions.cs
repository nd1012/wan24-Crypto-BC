using System.Collections.Concurrent;
using System.Reflection;
using wan24.Core;

//TODO Use reflection cache

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Internal reflection extensions
    /// </summary>
    internal static class InternalReflectionExtensions
    {
        /// <summary>
        /// Private byte array fields (key is the type)
        /// </summary>
        private static readonly ConcurrentDictionary<Type, FieldInfo[]> Fields = new();

        /// <summary>
        /// Clear all private byte array fields
        /// </summary>
        /// <param name="obj">Object</param>
        internal static void ClearPrivateByteArrayFields(this object obj)
        {
            Type type = obj.GetType();
            if (!Fields.TryGetValue(type, out FieldInfo[]? fields))
            {
                fields = (from fi in type.GetFieldsCached(BindingFlags.Instance | BindingFlags.NonPublic)
                          where fi.FieldType == typeof(byte[])
                          select fi).ToArray();
                Fields.TryAdd(type, fields);
            }
            for (int i = 0, len = fields.Length; i < len; (fields[i].GetValue(obj) as byte[])?.Clear(), i++) ;
        }
    }
}
