using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PasswordUtility
{
	public static class PopularPasswords
	{
		private static readonly Dictionary<int, Dictionary<string, bool>> PasswordCollection =
			new Dictionary<int, Dictionary<string, bool>>();

		internal static int MaxLength
		{
			get
			{
				Debug.Assert(PasswordCollection.Count > 0); // Should be initialized

				var iMaxLen = 0;
				foreach(var iLen in PasswordCollection.Keys)
				{
					if(iLen > iMaxLen) iMaxLen = iLen;
				}

				return iMaxLen;
			}
		}

		internal static bool ContainsLength(int nLength)
		{
			Dictionary<string, bool> dDummy;
			return PasswordCollection.TryGetValue(nLength, out dDummy);
		}

		public static bool IsPopularPassword(char[] vPassword)
		{
			ulong uDummy;
			return IsPopularPassword(vPassword, out uDummy);
		}

		public static bool IsPopularPassword(char[] vPassword, out ulong uPasswordCollectionize)
		{
		    if (vPassword == null)
		    {
		        throw new ArgumentNullException("vPassword");
		    }

		    if (vPassword.Length == 0)
		    {
		        uPasswordCollectionize = 0; 
                return false;
		    }

			var  str = new string(vPassword);

		    try
		    {
		        return IsPopularPasswordPriv(str, out uPasswordCollectionize);
		    }

			catch(Exception) { Debug.Assert(false); }

			uPasswordCollectionize = 0;
			return false;
		}

		private static bool IsPopularPasswordPriv(string str, out ulong uPasswordCollectionize)
		{
			Debug.Assert(PasswordCollection.Count > 0); // Should be initialized with data

			Dictionary<string, bool> d;
			if(!PasswordCollection.TryGetValue(str.Length, out d))
			{
				uPasswordCollectionize = 0;
				return false;
			}

			uPasswordCollectionize = (ulong)d.Count;
			return d.ContainsKey(str);
		}

		public static void Add(byte[] pbData, bool bGZipped)
		{
			try
			{
			    if (bGZipped)
			    {
			        pbData = MemUtil.Decompress(pbData);
			    }

				var strData = StrUtil.Utf8.GetString(pbData, 0, pbData.Length);
				if(string.IsNullOrEmpty(strData)) { Debug.Assert(false); return; }

			    if (!char.IsWhiteSpace(strData[strData.Length - 1]))
			    {
			        strData += "\n";
			    }

				var sb = new StringBuilder();
				for(var i = 0; i < strData.Length; ++i)
				{
					var ch = strData[i];

					if(char.IsWhiteSpace(ch))
					{
						var cc = sb.Length;
					    if (cc <= 0)
					    {
					        continue;
					    }

					    var strWord = sb.ToString();
					    Debug.Assert(strWord.Length == cc);

					    Dictionary<string, bool> d;
					    if(!PasswordCollection.TryGetValue(cc, out d))
					    {
					        d = new Dictionary<string, bool>();
					        PasswordCollection[cc] = d;
					    }

					    d[strWord] = true;
					    sb.Remove(0, cc);
					}
					else sb.Append(char.ToLower(ch));
				}
			}
			catch(Exception) { Debug.Assert(false); }
		}
	}
}
