using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using PasswordUtility.Cipher;

namespace PasswordUtility.Security
{
	[Flags]
	public enum PbCryptFlags
	{
		None = 0,
		Encrypt = 1,
		Decrypt = 2
	}

	public delegate void PbCryptDelegate(byte[] pbData, PbCryptFlags cf, long id);

	/// <summary>
	/// Represents a protected binary, i.e. a byte array that is encrypted
	/// in memory. A <c>ProtectedBinary</c> object is immutable and
	/// thread-safe.
	/// </summary>
	public sealed class ProtectedBinary : IEquatable<ProtectedBinary>
	{
		private const int BlockSize = 16;

		private static PbCryptDelegate encryptionDelegate;
		/// <summary>
		/// A plugin can provide a custom memory protection method
		/// by assigning a non-null delegate to this property.
		/// </summary>
		public static PbCryptDelegate ExtCrypt
		{
			get { return encryptionDelegate; }
			set { encryptionDelegate = value; }
		}

		// Local copy of the delegate that was used for encryption,
		// in order to allow correct decryption even when the global
		// delegate changes
		private PbCryptDelegate m_fExtCrypt;

		private enum PbMemProt
		{
			None = 0,
			ProtectedMemory,
			Salsa20,
			ExtCrypt
		}

		// ProtectedMemory is supported only on Windows 2000 SP3 and higher
		private static bool? protectedMemorySupported;
		private static bool ProtectedMemorySupported
		{
			get
			{

				var ob = protectedMemorySupported;
			    if (ob.HasValue)
			    {
			        return ob.Value;
			    }

				ob = false;
				try // Test whether ProtectedMemory is supported
				{
					// BlockSize * 3 in order to test encryption for multiple
					// blocks, but not introduce a power of 2 as factor
					var passwordBytes = new byte[BlockSize * 3];
					for(var i = 0; i < passwordBytes.Length; ++i) passwordBytes[i] = (byte)i;

					ProtectedMemory.Protect(passwordBytes, MemoryProtectionScope.SameProcess);

					for (var i = 0; i < passwordBytes.Length; ++i)
					{
					    if (passwordBytes[i] != (byte) i)
					    {
					        ob = true;
					        break;
					    }
					}
				}
				catch(Exception) { } // Windows 98 / ME

				protectedMemorySupported = ob;
				return ob.Value;
			}
		}

		private static long curId;
		private long longId;

		private byte[] passwordData; // Never null

		// The real length of the data; this value can be different from
		// m_pbData.Length, as the length of m_pbData always is a multiple
		// of BlockSize (required for ProtectedMemory)
		private uint dataLength;

		private bool isProtected; // Protection requested by the caller

		private PbMemProt passwordMemoryProtection = PbMemProt.None; // Actual protection

		private readonly object objSync = new object();

		private static byte[] keyBytes32 = null;

		/// <summary>
		/// A flag specifying whether the <c>ProtectedBinary</c> object has
		/// turned on memory protection or not.
		/// </summary>
		public bool IsProtected
		{
			get { return isProtected; }
		}

		/// <summary>
		/// Length of the stored data.
		/// </summary>
		public uint Length
		{
			get { return dataLength; }
		}

		/// <summary>
		/// Construct a new, empty protected binary data object.
		/// Protection is disabled.
		/// </summary>
		public ProtectedBinary()
		{
			Init(false, new byte[0]);
		}

		/// <summary>
		/// Construct a new protected binary data object.
		/// </summary>
		/// <param name="bEnableProtection">If this paremeter is <c>true</c>,
		/// the data will be encrypted in memory. If it is <c>false</c>, the
		/// data is stored in plain-text in the process memory.</param>
		/// <param name="pbData">Value of the protected object.
		/// The input parameter is not modified and
		/// <c>ProtectedBinary</c> doesn't take ownership of the data,
		/// i.e. the caller is responsible for clearing it.</param>
		public ProtectedBinary(bool bEnableProtection, byte[] pbData)
		{
			Init(bEnableProtection, pbData);
		}

		/// <summary>
		/// Construct a new protected binary data object. Copy the data from
		/// a <c>XorredBuffer</c> object.
		/// </summary>
		/// <param name="bEnableProtection">Enable protection or not.</param>
		/// <param name="xbProtected"><c>XorredBuffer</c> object used to
		/// initialize the <c>ProtectedBinary</c> object.</param>
		public ProtectedBinary(bool bEnableProtection, XorredBuffer xbProtected)
		{
			Debug.Assert(xbProtected != null);
			if(xbProtected == null) throw new ArgumentNullException("xbProtected");

			var pb = xbProtected.ReadPlainText();
			Init(bEnableProtection, pb);
			MemUtil.ZeroByteArray(pb);
		}

		private void Init(bool enableProtection, byte[] pbData)
		{
		    if (pbData == null)
		    {
		        throw new ArgumentNullException("pbData");
		    }
			longId = Interlocked.Increment(ref curId);

			isProtected = enableProtection;
			dataLength = (uint)pbData.Length;

			const int bs = BlockSize;
			var blocks = (int)dataLength / bs;
		    if ((blocks*bs) < (int) dataLength)
		    {
		        ++blocks;
		    }

			passwordData = new byte[blocks * bs];
			Array.Copy(pbData, passwordData, (int)dataLength);

			Encrypt();
		}

		private void Encrypt()
		{
			Debug.Assert(passwordMemoryProtection == PbMemProt.None);

		    if (!isProtected)
		    {
		        return;
		    }

		    if (passwordData.Length == 0)
		    {
		        return;
		    }

			var f = encryptionDelegate;
			if(f != null)
			{
				f(passwordData, PbCryptFlags.Encrypt, longId);

				m_fExtCrypt = f;
				passwordMemoryProtection = PbMemProt.ExtCrypt;
				return;
			}

		    if (ProtectedMemorySupported)
		    {
		        ProtectedMemory.Protect(passwordData, MemoryProtectionScope.SameProcess);

		        passwordMemoryProtection = PbMemProt.ProtectedMemory;
		        return;
		    }

		    var pbKey32 = keyBytes32;
		    if (pbKey32 == null)
		    {
		        pbKey32 = CryptoRandom.Instance.GetRandomBytes(32);

                var pbUpd = Interlocked.Exchange(ref keyBytes32, pbKey32);
		        if (pbUpd != null)
		        {
		            pbKey32 = pbUpd;
		        }
		    }

		    var cipher = new Salsa20Cipher(pbKey32, BitConverter.GetBytes(longId));
			cipher.Encrypt(passwordData, passwordData.Length, true);
			cipher.Dispose();
			passwordMemoryProtection = PbMemProt.Salsa20;
		}

		private void Decrypt()
		{
		    if (passwordData.Length == 0)
		    {
		        return;
		    }

		    if (passwordMemoryProtection == PbMemProt.ProtectedMemory)
		    {
		        ProtectedMemory.Unprotect(passwordData, MemoryProtectionScope.SameProcess);
		    }
			else if (passwordMemoryProtection == PbMemProt.Salsa20)
			{
			    var cipher = new Salsa20Cipher(keyBytes32, BitConverter.GetBytes(longId));
			    cipher.Encrypt(passwordData, passwordData.Length, true);
			    cipher.Dispose();
			}
			else if (passwordMemoryProtection == PbMemProt.ExtCrypt)
			{
			    m_fExtCrypt(passwordData, PbCryptFlags.Decrypt, longId);
			}
			else
			{
			    Debug.Assert(passwordMemoryProtection == PbMemProt.None);
			}

		    passwordMemoryProtection = PbMemProt.None;
		}

		/// <summary>
		/// Get a copy of the protected data as a byte array.
		/// Please note that the returned byte array is not protected and
		/// can therefore been read by any other application.
		/// Make sure that your clear it properly after usage.
		/// </summary>
		/// <returns>Unprotected byte array. This is always a copy of the internal
		/// protected data and can therefore be cleared safely.</returns>
		public byte[] ReadData()
		{
			if(dataLength == 0) return new byte[0];

			byte[] pbReturn = new byte[dataLength];

			lock(objSync)
			{
				Decrypt();
				Array.Copy(passwordData, pbReturn, (int)dataLength);
				Encrypt();
			}

			return pbReturn;
		}

		/// <summary>
		/// Read the protected data and return it protected with a sequence
		/// of bytes generated by a random stream.
		/// </summary>
		/// <param name="crsRandomSource">Random number source.</param>
		public byte[] ReadXorredData(CryptoRandomStream crsRandomSource)
		{
			Debug.Assert(crsRandomSource != null);
			if(crsRandomSource == null) throw new ArgumentNullException("crsRandomSource");

			byte[] pbData = ReadData();
			uint uLen = (uint)pbData.Length;

			byte[] randomPad = crsRandomSource.GetRandomBytes(uLen);
			Debug.Assert(randomPad.Length == pbData.Length);

			for(uint i = 0; i < uLen; ++i)
				pbData[i] ^= randomPad[i];

			return pbData;
		}

		private int? hash;
		public override int GetHashCode()
		{
		    if (hash.HasValue)
		    {
		        return hash.Value;
		    }

			var tempHash = (isProtected ? 0x7B11D289 : 0);

			var passwordBytes = ReadData();
			unchecked
			{
			    tempHash = passwordBytes.Aggregate(tempHash, (current, t) => (current << 3) + current + t);
			}

			MemUtil.ZeroByteArray(passwordBytes);

            hash = tempHash;
			return hash.Value;
		}

		public override bool Equals(object obj)
		{
			return Equals(obj as ProtectedBinary);
		}

		public bool Equals(ProtectedBinary other)
		{
		    if (other == null)
		    {
		        return false;
		    }

		    if (isProtected != other.isProtected)
		    {
		        return false;
		    }

		    if (dataLength != other.dataLength)
		    {
		        return false;
		    }

			var pbL = ReadData();
			var pbR = other.ReadData();
			var bEq = MemUtil.ArraysEqual(pbL, pbR);
			MemUtil.ZeroByteArray(pbL);
			MemUtil.ZeroByteArray(pbR);

            return bEq;
		}
	}
}
