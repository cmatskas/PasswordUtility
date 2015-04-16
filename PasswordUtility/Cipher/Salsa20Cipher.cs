using System;
using System.Diagnostics;

namespace PasswordUtility.Cipher
{
	public sealed class Salsa20Cipher : IDisposable
	{
		private readonly uint[] state = new uint[16];
		private readonly uint[] buffer = new uint[16]; // Working buffer

		private readonly byte[] output = new byte[64];
		private int outputPos = 64;

		private static readonly uint[] Sigma = {
			0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
		};

		public Salsa20Cipher(byte[] pbKey32, byte[] pbIv8)
		{
			KeySetup(pbKey32);
			IvSetup(pbIv8);
		}

		~Salsa20Cipher()
		{
			Dispose(false);
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		private void Dispose(bool bDisposing)
		{
			// Clear sensitive data
			Array.Clear(state, 0, state.Length);
			Array.Clear(buffer, 0, buffer.Length);
		}

		private void NextOutput()
		{
			var x = buffer; // Local alias for working buffer

			// Compiler/runtime might remove array bound checks after this
			if(x.Length < 16) throw new InvalidOperationException();

			Array.Copy(state, x, 16);

			unchecked
			{
				for(int i = 0; i < 10; ++i) // (int i = 20; i > 0; i -= 2)
				{
					x[ 4] ^= Rotl32(x[ 0] + x[12],  7);
					x[ 8] ^= Rotl32(x[ 4] + x[ 0],  9);
					x[12] ^= Rotl32(x[ 8] + x[ 4], 13);
					x[ 0] ^= Rotl32(x[12] + x[ 8], 18);
					x[ 9] ^= Rotl32(x[ 5] + x[ 1],  7);
					x[13] ^= Rotl32(x[ 9] + x[ 5],  9);
					x[ 1] ^= Rotl32(x[13] + x[ 9], 13);
					x[ 5] ^= Rotl32(x[ 1] + x[13], 18);
					x[14] ^= Rotl32(x[10] + x[ 6],  7);
					x[ 2] ^= Rotl32(x[14] + x[10],  9);
					x[ 6] ^= Rotl32(x[ 2] + x[14], 13);
					x[10] ^= Rotl32(x[ 6] + x[ 2], 18);
					x[ 3] ^= Rotl32(x[15] + x[11],  7);
					x[ 7] ^= Rotl32(x[ 3] + x[15],  9);
					x[11] ^= Rotl32(x[ 7] + x[ 3], 13);
					x[15] ^= Rotl32(x[11] + x[ 7], 18);
					x[ 1] ^= Rotl32(x[ 0] + x[ 3],  7);
					x[ 2] ^= Rotl32(x[ 1] + x[ 0],  9);
					x[ 3] ^= Rotl32(x[ 2] + x[ 1], 13);
					x[ 0] ^= Rotl32(x[ 3] + x[ 2], 18);
					x[ 6] ^= Rotl32(x[ 5] + x[ 4],  7);
					x[ 7] ^= Rotl32(x[ 6] + x[ 5],  9);
					x[ 4] ^= Rotl32(x[ 7] + x[ 6], 13);
					x[ 5] ^= Rotl32(x[ 4] + x[ 7], 18);
					x[11] ^= Rotl32(x[10] + x[ 9],  7);
					x[ 8] ^= Rotl32(x[11] + x[10],  9);
					x[ 9] ^= Rotl32(x[ 8] + x[11], 13);
					x[10] ^= Rotl32(x[ 9] + x[ 8], 18);
					x[12] ^= Rotl32(x[15] + x[14],  7);
					x[13] ^= Rotl32(x[12] + x[15],  9);
					x[14] ^= Rotl32(x[13] + x[12], 13);
					x[15] ^= Rotl32(x[14] + x[13], 18);
				}

			    for (var i = 0; i < 16; ++i)
			    {
			        x[i] += state[i];
			    }

				for(var i = 0; i < 16; ++i)
				{
					output[i << 2] = (byte)x[i];
					output[(i << 2) + 1] = (byte)(x[i] >> 8);
					output[(i << 2) + 2] = (byte)(x[i] >> 16);
					output[(i << 2) + 3] = (byte)(x[i] >> 24);
				}

				outputPos = 0;
				++state[8];
				if(state[8] == 0) ++state[9];
			}
		}

		private static uint Rotl32(uint x, int b)
		{
			unchecked
			{
				return ((x << b) | (x >> (32 - b)));
			}
		}

		private static uint U8To32Little(byte[] pb, int iOffset)
		{
			unchecked
			{
				return ((uint)pb[iOffset] | ((uint)pb[iOffset + 1] << 8) |
					((uint)pb[iOffset + 2] << 16) | ((uint)pb[iOffset + 3] << 24));
			}
		}

		private void KeySetup(byte[] k)
		{
			if(k == null) throw new ArgumentNullException("k");
			if(k.Length != 32) throw new ArgumentException();

			state[1] = U8To32Little(k, 0);
			state[2] = U8To32Little(k, 4);
			state[3] = U8To32Little(k, 8);
			state[4] = U8To32Little(k, 12);
			state[11] = U8To32Little(k, 16);
			state[12] = U8To32Little(k, 20);
			state[13] = U8To32Little(k, 24);
			state[14] = U8To32Little(k, 28);
			state[0] = Sigma[0];
			state[5] = Sigma[1];
			state[10] = Sigma[2];
			state[15] = Sigma[3];
		}

		private void IvSetup(byte[] pbIV)
		{
			if(pbIV == null) throw new ArgumentNullException("pbIV");
			if(pbIV.Length != 8) throw new ArgumentException();

			state[6] = U8To32Little(pbIV, 0);
			state[7] = U8To32Little(pbIV, 4);
			state[8] = 0;
			state[9] = 0;
		}

		public void Encrypt(byte[] m, int nByteCount, bool bXor)
		{
			if(m == null) throw new ArgumentNullException("m");
			if(nByteCount > m.Length) throw new ArgumentException();

			int nBytesRem = nByteCount, nOffset = 0;
			while(nBytesRem > 0)
			{
				Debug.Assert((outputPos >= 0) && (outputPos <= 64));
				if(outputPos == 64) NextOutput();
				Debug.Assert(outputPos < 64);

				int nCopy = Math.Min(64 - outputPos, nBytesRem);

				if(bXor) MemUtil.XorArray(output, outputPos, m, nOffset, nCopy);
				else Array.Copy(output, outputPos, m, nOffset, nCopy);

				outputPos += nCopy;
				nBytesRem -= nCopy;
				nOffset += nCopy;
			}
		}
	}
}
