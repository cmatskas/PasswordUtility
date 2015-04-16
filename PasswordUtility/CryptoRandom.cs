using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace PasswordUtility
{
	/// <summary>
	/// Cryptographically strong random number generator. The returned values
	/// are unpredictable and cannot be reproduced.
	/// <c>CryptoRandom</c> is a singleton class.
	/// </summary>
	public sealed class CryptoRandom
	{
		private byte[] pbEntropyPool = new byte[64];
		private uint counter;
		private readonly RNGCryptoServiceProvider mRng = new RNGCryptoServiceProvider();
		private ulong mUGeneratedBytesCount;

		private readonly object syncRoot = new object();

		private static CryptoRandom instance;
		public static CryptoRandom Instance
		{
			get
			{
			    if (instance != null)
			    {
			        return instance;
			    }

				instance = new CryptoRandom();
				return instance;
			}
		}

		/// <summary>
		/// Get the number of random bytes that this instance generated so far.
		/// Note that this number can be higher than the number of random bytes
		/// actually requested using the <c>GetRandomBytes</c> method.
		/// </summary>
		public ulong GeneratedBytesCount
		{
			get
			{
				ulong u;
				lock(syncRoot) { u = mUGeneratedBytesCount; }
				return u;
			}
		}

		/// <summary>
		/// Event that is triggered whenever the internal <c>GenerateRandom256</c>
		/// method is called to generate random bytes.
		/// </summary>
		public event EventHandler GenerateRandom256Pre;

		private CryptoRandom()
		{
			var r = new Random();
			counter = (uint)r.Next();

			AddEntropy(GetSystemData(r));
			AddEntropy(GetCspData());
		}

		/// <summary>
		/// Update the internal seed of the random number generator based
		/// on entropy data.
		/// This method is thread-safe.
		/// </summary>
		/// <param name="pbEntropy">Entropy bytes.</param>
		public void AddEntropy(byte[] pbEntropy)
		{
		    if (pbEntropy == null || pbEntropy.Length == 0)
		    {
		        Debug.Assert(false);
		    }

		    var pbNewData = pbEntropy;
			if(pbEntropy.Length >= 64)
			{
				var shaNew = new SHA256Managed();
				pbNewData = shaNew.ComputeHash(pbEntropy);
			}

		    using (var ms = new MemoryStream())
		    {
		        lock (syncRoot)
		        {
		            ms.Write(pbEntropyPool, 0, pbEntropyPool.Length);
		            ms.Write(pbNewData, 0, pbNewData.Length);

		            var pbFinal = ms.ToArray();
		            var shaPool = new SHA256Managed();
		            pbEntropyPool = shaPool.ComputeHash(pbFinal);
		        }
		    }
		}

		private static byte[] GetSystemData(Random rWeak)
		{
		    byte[] pbAll;
		    using (var ms = new MemoryStream())
		    {
		        var pb = MemUtil.UInt32ToBytes((uint) Environment.TickCount);
		        ms.Write(pb, 0, pb.Length);

		        pb = TimeUtil.PackTime(DateTime.Now);
		        ms.Write(pb, 0, pb.Length);

		        pb = MemUtil.UInt32ToBytes((uint) rWeak.Next());
		        ms.Write(pb, 0, pb.Length);

                pb = MemUtil.UInt32ToBytes((uint)Environment.OSVersion.Platform);
		        ms.Write(pb, 0, pb.Length);

		        pb = Guid.NewGuid().ToByteArray();
		        ms.Write(pb, 0, pb.Length);

		        pbAll = ms.ToArray();
		        ms.Close();
		    }

		    return pbAll;
		}

		private byte[] GetCspData()
		{
			var pbCspRandom = new byte[32];
			mRng.GetBytes(pbCspRandom);
			return pbCspRandom;
		}

		private byte[] GenerateRandom256()
		{
		    if (GenerateRandom256Pre != null)
		    {
		        GenerateRandom256Pre(this, EventArgs.Empty);
		    }

			byte[] pbFinal;
			lock(syncRoot)
			{
				unchecked { counter += 386047; } // Prime number
				var pbCounter = MemUtil.UInt32ToBytes(counter);

				var pbCspRandom = GetCspData();

			    using (var ms = new MemoryStream())
			    {
			        ms.Write(pbEntropyPool, 0, pbEntropyPool.Length);
			        ms.Write(pbCounter, 0, pbCounter.Length);
			        ms.Write(pbCspRandom, 0, pbCspRandom.Length);
			        pbFinal = ms.ToArray();
			        Debug.Assert(pbFinal.Length == (pbEntropyPool.Length +
			                                        pbCounter.Length + pbCspRandom.Length));
			    }

			    mUGeneratedBytesCount += 32;
			}

			var sha256 = new SHA256Managed();
			return sha256.ComputeHash(pbFinal);
		}

		/// <summary>
		/// Get a number of cryptographically strong random bytes.
		/// This method is thread-safe.
		/// </summary>
		/// <param name="uRequestedBytes">Number of requested random bytes.</param>
		/// <returns>A byte array consisting of <paramref name="uRequestedBytes" />
		/// random bytes.</returns>
		public byte[] GetRandomBytes(uint uRequestedBytes)
		{
			if(uRequestedBytes == 0) return new byte[0]; // Allow zero-length array

			var pbRes = new byte[uRequestedBytes];
			long lPos = 0;

			while(uRequestedBytes != 0)
			{
				var pbRandom256 = GenerateRandom256();
				Debug.Assert(pbRandom256.Length == 32);

				var lCopy = (long)((uRequestedBytes < 32) ? uRequestedBytes : 32);

				Array.Copy(pbRandom256, 0, pbRes, (int)lPos, (int)lCopy);

				lPos += lCopy;
				uRequestedBytes -= (uint)lCopy;
			}

			Debug.Assert((int)lPos == pbRes.Length);
			return pbRes;
		}
	}
}
