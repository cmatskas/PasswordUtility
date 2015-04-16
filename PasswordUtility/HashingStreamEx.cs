using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace PasswordUtility
{
	public sealed class HashingStreamEx : Stream
	{
		private readonly Stream baseStream;
		private readonly bool writing;
		private HashAlgorithm hash;

		private byte[] finalHashBytes = null;

		public byte[] Hash
		{
			get { return finalHashBytes; }
		}

		public override bool CanRead
		{
			get { return !writing; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return writing; }
		}

		public override long Length
		{
			get { return baseStream.Length; }
		}

		public override long Position
		{
			get { return baseStream.Position; }
			set { throw new NotSupportedException(); }
		}

		public HashingStreamEx(Stream sBaseStream, bool bWriting, HashAlgorithm hashAlgorithm)
		{
			if(sBaseStream == null) throw new ArgumentNullException("sBaseStream");

			baseStream = sBaseStream;
			writing = bWriting;


			hash = (hashAlgorithm ?? new SHA256Managed());
			if(hash == null) { Debug.Assert(false); return; }

			// Validate hash algorithm
			if((!hash.CanReuseTransform) || (!hash.CanTransformMultipleBlocks) ||
				(hash.InputBlockSize != 1) || (hash.OutputBlockSize != 1))
			{
				hash = null;
			}
		}

		public override void Flush()
		{
			baseStream.Flush();
		}

		public override void Close()
		{
			if(hash != null)
			{
				try
				{
					hash.TransformFinalBlock(new byte[0], 0, 0);

					finalHashBytes = hash.Hash;
				}
				catch(Exception) { Debug.Assert(false); }

				hash = null;
			}

			baseStream.Close();
		}

		public override long Seek(long lOffset, SeekOrigin soOrigin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long lValue)
		{
			throw new NotSupportedException();
		}

		public override int Read(byte[] pbBuffer, int nOffset, int nCount)
		{
			if(writing) throw new InvalidOperationException();

			int nRead = baseStream.Read(pbBuffer, nOffset, nCount);
			int nPartialRead = nRead;
			while((nRead < nCount) && (nPartialRead != 0))
			{
				nPartialRead = baseStream.Read(pbBuffer, nOffset + nRead,
					nCount - nRead);
				nRead += nPartialRead;
			}

		    if ((hash != null) && (nRead > 0))
		    {
		        hash.TransformBlock(pbBuffer, nOffset, nRead, pbBuffer, nOffset);
		    }

			return nRead;
		}

		public override void Write(byte[] pbBuffer, int nOffset, int nCount)
		{
			if(!writing) throw new InvalidOperationException();

		    if ((hash != null) && (nCount > 0))
		    {
		        hash.TransformBlock(pbBuffer, nOffset, nCount, pbBuffer, nOffset);
		    }

			baseStream.Write(pbBuffer, nOffset, nCount);
		}
	}
}
