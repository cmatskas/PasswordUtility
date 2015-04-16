using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PasswordUtility
{
	public sealed class PwUuid : IComparable<PwUuid>, IEquatable<PwUuid>
	{
		/// <summary>
		/// Standard size in bytes of a UUID.
		/// </summary>
		public const uint UuidSize = 16;

		/// <summary>
		/// Zero UUID (all bytes are zero).
		/// </summary>
		public static readonly PwUuid Zero = new PwUuid(false);

		private byte[] uidBytes; // Never null after constructor

		/// <summary>
		/// Get the 16 UUID bytes.
		/// </summary>
		public byte[] UuidBytes
		{
			get { return uidBytes; }
		}

		/// <summary>
		/// Construct a new UUID object.
		/// </summary>
        /// <param name="createNew">If this parameter is <c>true</c>, a new
		/// UUID is generated. If it is <c>false</c>, the UUID is initialized
		/// to zero.</param>
		public PwUuid(bool createNew)
		{
		    if (createNew)
		    {
		        CreateNew();
		        return;
		    }
            
		    SetZero();
		}

		/// <summary>
		/// Construct a new UUID object.
		/// </summary>
		/// <param name="uuidBytes">Initial value of the <c>PwUuid</c> object.</param>
		public PwUuid(byte[] uuidBytes)
		{
			SetValue(uuidBytes);
		}

		/// <summary>
		/// Create a new, random UUID.
		/// </summary>
		/// <returns>Returns <c>true</c> if a random UUID has been generated,
		/// otherwise it returns <c>false</c>.</returns>
		private void CreateNew()
		{
			Debug.Assert(uidBytes == null); // Only call from constructor
			while(true)
			{
				uidBytes = Guid.NewGuid().ToByteArray();

				if((uidBytes == null) || (uidBytes.Length != (int)UuidSize))
				{
					Debug.Assert(false);
					throw new InvalidOperationException();
				}

				// Zero is a reserved value -- do not generate Zero
			    if (!Equals(Zero))
			    {
			        break;
			    }

				Debug.Assert(false);
			}
		}

		private void SetValue(byte[] uuidBytes)
		{
			Debug.Assert((uuidBytes != null) && (uuidBytes.Length == (int)UuidSize));
		    if (uuidBytes == null)
		    {
		        throw new ArgumentNullException("uuidBytes");
		    }

		    if (uuidBytes.Length != (int) UuidSize)
		    {
		        throw new ArgumentException();
		    }

			Debug.Assert(uidBytes == null); // Only call from constructor
			uidBytes = new byte[UuidSize];

			Array.Copy(uuidBytes, uidBytes, (int)UuidSize);
		}

		private void SetZero()
		{
			Debug.Assert(uidBytes == null); // Only call from constructor
			uidBytes = new byte[UuidSize];

			// Array.Clear(uidBytes, 0, (int)UuidSize);
#if DEBUG
			var l = new List<byte>(uidBytes);
			Debug.Assert(l.TrueForAll(bt => (bt == 0)));
#endif
		}

		public override bool Equals(object obj)
		{
			return Equals(obj as PwUuid);
		}

		public bool Equals(PwUuid other)
		{
		    if (other == null)
		    {
		        Debug.Assert(false); return false;
		    }

			for(var i = 0; i < (int)UuidSize; ++i)
			{
				if(uidBytes[i] != other.uidBytes[i]) return false;
			}

			return true;
		}

		private int hash;
		public override int GetHashCode()
		{
            if (hash == 0)
		    {
                hash = (int)MemUtil.Hash32(uidBytes, 0, uidBytes.Length);
		    }
            return hash;
		}

		public int CompareTo(PwUuid other)
		{
			if(other == null)
			{
				Debug.Assert(false);
				throw new ArgumentNullException("other");
			}

			for(var i = 0; i < (int)UuidSize; ++i)
			{
			    if (uidBytes[i] < other.uidBytes[i])
			    {
			        return -1;
			    }

			    if (uidBytes[i] > other.uidBytes[i])
			    {
			        return 1;
			    }
			}

			return 0;
		}

		/// <summary>
		/// Convert the UUID to its string representation.
		/// </summary>
		/// <returns>String containing the UUID value.</returns>
		public string ToHexString()
		{
			return MemUtil.ByteArrayToHexString(uidBytes);
		}

#if DEBUG
		public override string ToString()
		{
			return ToHexString();
		}
#endif
	}
}
