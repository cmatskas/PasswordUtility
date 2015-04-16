using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace PasswordUtility.Cipher
{
	/// <summary>
	/// Pool of encryption/decryption algorithms (ciphers).
	/// </summary>
	public sealed class CipherPool
	{
		private readonly List<ICipherEngine> ciphers = new List<ICipherEngine>();
		private static CipherPool poolGlobal;

		/// <summary>
		/// Reference to the global cipher pool.
		/// </summary>
		public static CipherPool GlobalPool
		{
			get
			{
				if(poolGlobal != null) return poolGlobal;

				poolGlobal = new CipherPool();
				poolGlobal.AddCipher(new StandardAesEngine());

				return poolGlobal;
			}
		}

		/// <summary>
		/// Remove all cipher engines from the current pool.
		/// </summary>
		public void Clear()
		{
			ciphers.Clear();
		}

	    /// <summary>
	    /// Add a cipher engine to the pool.
	    /// </summary>
	    /// <param name="csEngine">Cipher engine to add. Must not be <c>null</c>.</param>
	    public void AddCipher(ICipherEngine csEngine)
	    {
	        Debug.Assert(csEngine != null);
	        if (csEngine == null)
	        {
	            throw new ArgumentNullException("csEngine");
	        }

	        // Return if a cipher with that ID is registered already.
	        for (var i = 0; i < ciphers.Count; ++i)
	        {
	            if (ciphers[i].CipherUuid.Equals(csEngine.CipherUuid))
	            {
	                return;
	            }
	        }

    	    ciphers.Add(csEngine);
		}

		/// <summary>
		/// Get a cipher identified by its UUID.
		/// </summary>
		/// <param name="uuidCipher">UUID of the cipher to return.</param>
		/// <returns>Reference to the requested cipher. If the cipher is
		/// not found, <c>null</c> is returned.</returns>
		public ICipherEngine GetCipher(PwUuid uuidCipher)
		{
			foreach(ICipherEngine iEngine in ciphers)
			{
				if(iEngine.CipherUuid.Equals(uuidCipher))
					return iEngine;
			}

			return null;
		}

		/// <summary>
		/// Get the index of a cipher. This index is temporary and should
		/// not be stored or used to identify a cipher.
		/// </summary>
		/// <param name="uuidCipher">UUID of the cipher.</param>
		/// <returns>Index of the requested cipher. Returns <c>-1</c> if
		/// the specified cipher is not found.</returns>
		public int GetCipherIndex(PwUuid uuidCipher)
		{
			for(int i = 0; i < ciphers.Count; ++i)
			{
				if(ciphers[i].CipherUuid.Equals(uuidCipher))
					return i;
			}

			Debug.Assert(false);
			return -1;
		}

		/// <summary>
		/// Get the index of a cipher. This index is temporary and should
		/// not be stored or used to identify a cipher.
		/// </summary>
		/// <param name="strDisplayName">Name of the cipher. Note that
		/// multiple ciphers can have the same name. In this case, the
		/// first matching cipher is returned.</param>
		/// <returns>Cipher with the specified name or <c>-1</c> if
		/// no cipher with that name is found.</returns>
		public int GetCipherIndex(string strDisplayName)
		{
			for(int i = 0; i < ciphers.Count; ++i)
				if(ciphers[i].DisplayName == strDisplayName)
					return i;

			Debug.Assert(false);
			return -1;
		}

		/// <summary>
		/// Get the number of cipher engines in this pool.
		/// </summary>
		public int EngineCount
		{
			get { return ciphers.Count; }
		}

		/// <summary>
		/// Get the cipher engine at the specified position. Throws
		/// an exception if the index is invalid. You can use this
		/// to iterate over all ciphers, but do not use it to
		/// identify ciphers.
		/// </summary>
		/// <param name="nIndex">Index of the requested cipher engine.</param>
		/// <returns>Reference to the cipher engine at the specified
		/// position.</returns>
		public ICipherEngine this[int nIndex]
		{
			get
			{
				if((nIndex < 0) || (nIndex >= ciphers.Count))
					throw new ArgumentOutOfRangeException("nIndex");

				return ciphers[nIndex];
			}
		}
	}
}
