using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;

namespace PasswordUtility.Cipher
{
	/// <summary>
	/// Standard AES cipher implementation.
	/// </summary>
	public sealed class StandardAesEngine : ICipherEngine
	{
		private const CipherMode TheCipherMode = CipherMode.CBC;
		private const PaddingMode CipherPadding = PaddingMode.PKCS7;

		private static PwUuid uidAes;

		/// <summary>
		/// UUID of the cipher engine. This ID uniquely identifies the
		/// AES engine. Must not be used by other ciphers.
		/// </summary>
		public static PwUuid AesUuid
		{
		    get
		    {
		        return uidAes ?? (uidAes = new PwUuid(new byte[]
		        {
		            0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
		            0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF
		        }));
		    }
		}

		/// <summary>
		/// Get the UUID of this cipher engine as <c>PwUuid</c> object.
		/// </summary>
		public PwUuid CipherUuid
		{
			get { return AesUuid; }
		}

	    /// <summary>
	    /// Get a displayable name describing this cipher engine.
	    /// </summary>
	    public string DisplayName
	    {
	        get { return "AES Encryption"; }
	    }

	    private static void ValidateArguments(Stream stream, bool encrypt, byte[] keyBytes, byte[] ivBytes)
		{
			Debug.Assert(stream != null);
	        if (stream == null)
	        {
	            throw new ArgumentNullException("stream");
	        }

			Debug.Assert(keyBytes != null);
	        if (keyBytes == null)
	        {
	            throw new ArgumentNullException("keyBytes");
	        }

			Debug.Assert(keyBytes.Length == 32);
	        if (keyBytes.Length != 32)
	        {
	            throw new ArgumentException("Key must be 256 bits wide!");
	        }

			Debug.Assert(ivBytes != null);
	        if (ivBytes == null)
	        {
	            throw new ArgumentNullException("ivBytes");
	        }

			Debug.Assert(ivBytes.Length == 16);
	        if (ivBytes.Length != 16)
	        {
	            throw new ArgumentException("Initialization vector must be 128 bits wide!");
	        }

			if(encrypt)
			{
				Debug.Assert(stream.CanWrite);
			    if (stream.CanWrite == false)
			    {
			        throw new ArgumentException("Stream must be writable!");
			    }
			}
			else // Decrypt
			{
				Debug.Assert(stream.CanRead);
			    if (stream.CanRead == false)
			    {
			        throw new ArgumentException("Encrypted stream must be readable!");
			    }
			}
		}

		private static Stream CreateStream(Stream s, bool encrypt, byte[] keyBytes, byte[] iVBytes)
		{
			ValidateArguments(s, encrypt, keyBytes, iVBytes);

			var localIvBytes = new byte[16];
			Array.Copy(iVBytes, localIvBytes, 16);

			var localKeyBytes = new byte[32];
			Array.Copy(keyBytes, localKeyBytes, 32);

			var rijndaelManaged = new RijndaelManaged();
			if(rijndaelManaged.BlockSize != 128) // AES block size
			{
				Debug.Assert(false);
			}

			rijndaelManaged.IV = localIvBytes;
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.Key = localKeyBytes;
			rijndaelManaged.Mode = TheCipherMode;
			rijndaelManaged.Padding = CipherPadding;

			var iTransform = (encrypt ? rijndaelManaged.CreateEncryptor() : rijndaelManaged.CreateDecryptor());
			Debug.Assert(iTransform != null);
		    if (iTransform == null)
		    {
		        throw new SecurityException("Unable to create Rijndael transform!");
		    }

		    return new CryptoStream(s, iTransform, encrypt
		        ? CryptoStreamMode.Write
		        : CryptoStreamMode.Read);
		}

		public Stream EncryptStream(Stream sPlainText, byte[] keyBytes, byte[] ivBytes)
		{
			return CreateStream(sPlainText, true, keyBytes, ivBytes);
		}

		public Stream DecryptStream(Stream sEncrypted, byte[] keyBytes, byte[] ivBytes)
		{
			return CreateStream(sEncrypted, false, keyBytes, ivBytes);
		}
	}
}
