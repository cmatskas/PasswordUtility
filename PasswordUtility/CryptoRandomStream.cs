using System;
using System.Diagnostics;
using System.Security.Cryptography;
using PasswordUtility.Cipher;

namespace PasswordUtility
{
	/// <summary>
	/// Algorithms supported by <c>CryptoRandomStream</c>.
	/// </summary>
	public enum CrsAlgorithm
	{
		/// <summary>
		/// Not supported.
		/// </summary>
		Null = 0,

		/// <summary>
		/// A variant of the ARCFour algorithm (RC4 incompatible).
		/// </summary>
		ArcFourVariant = 1,

		/// <summary>
		/// Salsa20 stream cipher algorithm.
		/// </summary>
		Salsa20 = 2,

		Count = 3
	}

	/// <summary>
	/// A random stream class. The class is initialized using random
	/// bytes provided by the caller. The produced stream has random
	/// properties, but for the same seed always the same stream
	/// is produced, i.e. this class can be used as stream cipher.
	/// </summary>
	public sealed class CryptoRandomStream
	{
		private readonly CrsAlgorithm crsAlgorithm;

		private readonly byte[] state = null;
		private byte firstCounter = 0;
		private byte secondCounter = 0;

		private readonly Salsa20Cipher salsa20;

		/// <summary>
		/// Construct a new cryptographically secure random stream object.
		/// </summary>
		/// <param name="genAlgorithm">Algorithm to use.</param>
		/// <param name="pbKey">Initialization key. Must not be <c>null</c> and
		/// must contain at least 1 byte.</param>
		/// <exception cref="System.ArgumentNullException">Thrown if the
		/// <paramref name="pbKey" /> parameter is <c>null</c>.</exception>
		/// <exception cref="System.ArgumentException">Thrown if the
		/// <paramref name="pbKey" /> parameter contains no bytes or the
		/// algorithm is unknown.</exception>
		public CryptoRandomStream(CrsAlgorithm genAlgorithm, byte[] pbKey)
		{
			crsAlgorithm = genAlgorithm;

			Debug.Assert(pbKey != null); if(pbKey == null) throw new ArgumentNullException("pbKey");

			uint uKeyLen = (uint)pbKey.Length;
			Debug.Assert(uKeyLen != 0); if(uKeyLen == 0) throw new ArgumentException();

			if(genAlgorithm == CrsAlgorithm.ArcFourVariant)
			{
				// Fill the state linearly
				state = new byte[256];
				for(uint w = 0; w < 256; ++w) state[w] = (byte)w;

				unchecked
				{
				    byte j = 0;
				    uint inxKey = 0;
					for(uint w = 0; w < 256; ++w) // Key setup
					{
						j += (byte)(state[w] + pbKey[inxKey]);

						var t = state[0];
						state[0] = state[j];
						state[j] = t;

						++inxKey;
						if(inxKey >= uKeyLen) inxKey = 0;
					}
				}

				GetRandomBytes(512); // Increases security, see cryptanalysis
			}
			else if(genAlgorithm == CrsAlgorithm.Salsa20)
			{
				var sha256 = new SHA256Managed();
				var pbKey32 = sha256.ComputeHash(pbKey);
				var pbIv = new byte[] { 0xE8, 0x30, 0x09, 0x4B,
					0x97, 0x20, 0x5D, 0x2A }; // Unique constant

				salsa20 = new Salsa20Cipher(pbKey32, pbIv);
			}
			else // Unknown algorithm
			{
				Debug.Assert(false);
			}
		}

		/// <summary>
		/// Get <paramref name="uRequestedCount" /> random bytes.
		/// </summary>
		/// <param name="uRequestedCount">Number of random bytes to retrieve.</param>
		/// <returns>Returns <paramref name="uRequestedCount" /> random bytes.</returns>
		public byte[] GetRandomBytes(uint uRequestedCount)
		{
			if(uRequestedCount == 0) return new byte[0];

			byte[] pbRet = new byte[uRequestedCount];

			if(crsAlgorithm == CrsAlgorithm.ArcFourVariant)
			{
				unchecked
				{
					for(uint w = 0; w < uRequestedCount; ++w)
					{
						++firstCounter;
						secondCounter += state[firstCounter];

						byte t = state[firstCounter]; // Swap entries
						state[firstCounter] = state[secondCounter];
						state[secondCounter] = t;

						t = (byte)(state[firstCounter] + state[secondCounter]);
						pbRet[w] = state[t];
					}
				}
			}
			else if (crsAlgorithm == CrsAlgorithm.Salsa20)
			{
			    salsa20.Encrypt(pbRet, pbRet.Length, false);
			}
			else
			{
			    Debug.Assert(false);
			}

			return pbRet;
		}

		public ulong GetRandomUInt64()
		{
			var pb = GetRandomBytes(8);

			unchecked
			{
				return (pb[0]) | ((ulong)pb[1] << 8) |
					((ulong)pb[2] << 16) | ((ulong)pb[3] << 24) |
					((ulong)pb[4] << 32) | ((ulong)pb[5] << 40) |
					((ulong)pb[6] << 48) | ((ulong)pb[7] << 56);
			}
		}
	}
}
