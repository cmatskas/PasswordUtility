using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PasswordUtility.Native;
using PasswordUtility.PasswordGenerator;
using PasswordUtility.Security;

namespace PasswordUtility
{
	/// <summary>
	/// Character stream class.
	/// </summary>
	public sealed class CharStream
	{
		private readonly string characterString;
		private int position;

		public CharStream(string str)
		{
			Debug.Assert(str != null);
			if(str == null) throw new ArgumentNullException("str");

			characterString = str;
		}

		public void Seek(SeekOrigin org, int nSeek)
		{
		    if (org == SeekOrigin.Begin)
		    {
		        position = nSeek;
		    }
			else if (org == SeekOrigin.Current)
			{
			    position += nSeek;
			}
			else if (org == SeekOrigin.End)
			{
			    position = characterString.Length + nSeek;
			}
		}

		public char ReadChar()
		{
		    if (position < 0)
		    {
		        return char.MinValue;
		    }
		    if (position >= characterString.Length)
		    {
		        return char.MinValue;
		    }

			var chRet = characterString[position];
			++position;
			return chRet;
		}

		public char ReadChar(bool bSkipWhiteSpace)
		{
		    if (bSkipWhiteSpace == false)
		    {
		        return ReadChar();
		    }

			while(true)
			{
				char ch = ReadChar();

				if((ch != ' ') && (ch != '\t') && (ch != '\r') && (ch != '\n'))
					return ch;
			}
		}

		public char PeekChar()
		{
			if(position < 0) return char.MinValue;
			if(position >= characterString.Length) return char.MinValue;

			return characterString[position];
		}

		public char PeekChar(bool bSkipWhiteSpace)
		{
			if(bSkipWhiteSpace == false) return PeekChar();

			int iIndex = position;
			while(true)
			{
				if(iIndex < 0) return char.MinValue;
				if(iIndex >= characterString.Length) return char.MinValue;

				char ch = characterString[iIndex];

				if((ch != ' ') && (ch != '\t') && (ch != '\r') && (ch != '\n'))
					return ch;

				++iIndex;
			}
		}
	}

	public enum StrEncodingType
	{
		Unknown = 0,
		Default,
		Ascii,
		Utf7,
		Utf8,
		Utf16Le,
		Utf16Be,
		Utf32Le,
		Utf32Be
	}

	public sealed class StrEncodingInfo
	{
		private readonly StrEncodingType encodingType;
		public StrEncodingType Type
		{
			get { return encodingType; }
		}

		private readonly string name;
		public string Name
		{
			get { return name; }
		}

		private readonly Encoding encoding;
		public Encoding Encoding
		{
			get { return encoding; }
		}

		private readonly uint codePoint;
		/// <summary>
		/// Size of a character in bytes.
		/// </summary>
		public uint CodePointSize
		{
			get { return codePoint; }
		}

		private readonly byte[] signatureBytes;
		/// <summary>
		/// Start signature of the text (byte order mark).
		/// May be <c>null</c> or empty, if no signature is known.
		/// </summary>
		public byte[] StartSignature
		{
			get { return signatureBytes; }
		}

		public StrEncodingInfo(StrEncodingType t, string strName, Encoding enc,
			uint cbCodePoint, byte[] vStartSig)
		{
			if(strName == null) throw new ArgumentNullException("strName");
			if(enc == null) throw new ArgumentNullException("enc");
			if(cbCodePoint <= 0) throw new ArgumentOutOfRangeException("cbCodePoint");

			encodingType = t;
			name = strName;
			encoding = enc;
			codePoint = cbCodePoint;
			signatureBytes = vStartSig;
		}
	}

	/// <summary>
	/// A class containing various string helper methods.
	/// </summary>
	public static class StrUtil
	{
		public const StringComparison CaseIgnoreCmp = StringComparison.OrdinalIgnoreCase;

		public static StringComparer CaseIgnoreComparer
		{
			get { return StringComparer.OrdinalIgnoreCase; }
		}

	    public static bool RightToLeft { get; set; }

	    private static UTF8Encoding utfEncoding;
		public static UTF8Encoding Utf8
		{
			get { return utfEncoding ?? (utfEncoding = new UTF8Encoding(false, false)); }
		}

		private static List<StrEncodingInfo> encodingInfoList;
		public static IEnumerable<StrEncodingInfo> Encodings
		{
			get
			{
			    if (encodingInfoList != null)
			    {
			        return encodingInfoList;
			    }

			    var list = new List<StrEncodingInfo>
			    {
			        new StrEncodingInfo(
			            StrEncodingType.Default,
			            Encoding.Default.EncodingName,
			            Encoding.Default,
			            (uint) Encoding.Default.GetBytes("a").Length,
			            null),
			        new StrEncodingInfo(StrEncodingType.Ascii,
			            "ASCII", Encoding.ASCII, 1, null),
			        new StrEncodingInfo(StrEncodingType.Utf7,
			            "Unicode (UTF-7)", Encoding.UTF7, 1, null),
			        new StrEncodingInfo(StrEncodingType.Utf8,
			            "Unicode (UTF-8)", Utf8, 1, new byte[] {0xEF, 0xBB, 0xBF}),
			        new StrEncodingInfo(StrEncodingType.Utf16Le,
			            "Unicode (UTF-16 LE)", new UnicodeEncoding(false, false),
			            2, new byte[] {0xFF, 0xFE}),
			        new StrEncodingInfo(StrEncodingType.Utf16Be,
			            "Unicode (UTF-16 BE)", new UnicodeEncoding(true, false),
			            2, new byte[] {0xFE, 0xFF}),
			        new StrEncodingInfo(StrEncodingType.Utf32Le,
			            "Unicode (UTF-32 LE)", new UTF32Encoding(false, false),
			            4, new byte[] {0xFF, 0xFE, 0x0, 0x0}),
			        new StrEncodingInfo(StrEncodingType.Utf32Be,
			            "Unicode (UTF-32 BE)", new UTF32Encoding(true, false),
			            4, new byte[] {0x0, 0x0, 0xFE, 0xFF})
			    };


			    encodingInfoList = list;
				return list;
			}
		}

		// public static string RtfPar
		// {
		//	// get { return (m_bRtl ? "\\rtlpar " : "\\par "); }
		//	get { return "\\par "; }
		// }

		// /// <summary>
		// /// Convert a string into a valid RTF string.
		// /// </summary>
		// /// <param name="str">Any string.</param>
		// /// <returns>RTF-encoded string.</returns>
		// public static string MakeRtfString(string str)
		// {
		//	Debug.Assert(str != null); if(str == null) throw new ArgumentNullException("str");
		//	str = str.Replace("\\", "\\\\");
		//	str = str.Replace("\r", string.Empty);
		//	str = str.Replace("{", "\\{");
		//	str = str.Replace("}", "\\}");
		//	str = str.Replace("\n", StrUtil.RtfPar);
		//	StringBuilder sbEncoded = new StringBuilder();
		//	for(int i = 0; i < str.Length; ++i)
		//	{
		//		char ch = str[i];
		//		if((int)ch >= 256)
		//			sbEncoded.Append(StrUtil.RtfEncodeChar(ch));
		//		else sbEncoded.Append(ch);
		//	}
		//	return sbEncoded.ToString();
		// }

		public static string RtfEncodeChar(char ch)
		{
			// Unicode character values must be encoded using
			// 16-bit numbers (decimal); Unicode values greater
			// than 32767 must be expressed as negative numbers
			short sh = (short)ch;
			return ("\\u" + sh.ToString(NumberFormatInfo.InvariantInfo) + "?");
		}

		/// <summary>
		/// Convert a string into a valid HTML sequence representing that string.
		/// </summary>
		/// <param name="str">String to convert.</param>
		/// <returns>String, HTML-encoded.</returns>
		public static string StringToHtml(string str)
		{
			Debug.Assert(str != null); if(str == null) throw new ArgumentNullException("str");

			str = str.Replace(@"&", @"&amp;");
			str = str.Replace(@"<", @"&lt;");
			str = str.Replace(@">", @"&gt;");
			str = str.Replace("\"", @"&quot;");
			str = str.Replace("\'", @"&#39;");

			str = NormalizeNewLines(str, false);
			str = str.Replace("\n", @"<br />" + Environment.NewLine);

			return str;
		}

		public static string XmlToString(string str)
		{
		    if (str == null)
		    {
		        throw new ArgumentNullException("str");
		    }

			str = str.Replace(@"&amp;", @"&");
			str = str.Replace(@"&lt;", @"<");
			str = str.Replace(@"&gt;", @">");
			str = str.Replace(@"&quot;", "\"");
			str = str.Replace(@"&#39;", "\'");

			return str;
		}

		public static string ReplaceCaseInsensitive(string stringToReplace, string strFind,
			string strNew)
		{
		    if (stringToReplace == null)
		    {
		        return null;
		    }

		    if (strFind == null)
		    {
		        return stringToReplace;
		    }

		    if (strNew == null)
		    {
		        return stringToReplace;
		    }

			string str = stringToReplace;

			int nPos = 0;
			while(nPos < str.Length)
			{
				nPos = str.IndexOf(strFind, nPos, StringComparison.OrdinalIgnoreCase);
				if(nPos < 0) break;

				str = str.Remove(nPos, strFind.Length);
				str = str.Insert(nPos, strNew);

				nPos += strNew.Length;
			}

			return str;
		}

		/// <summary>
		/// Split up a command-line into application and argument.
		/// </summary>
		public static void SplitCommandLine(string strCmdLine, out string applicationPath, out string arguments)
		{
		    if (strCmdLine == null)
		    {
		        throw new ArgumentNullException("strCmdLine");
		    }

			var str = strCmdLine.Trim();

            applicationPath = null; 
            arguments = null;

			if(str.StartsWith("\""))
			{
				var nSecond = str.IndexOf('\"', 1);
				if(nSecond >= 1)
				{
					applicationPath = str.Substring(1, nSecond - 1).Trim();
                    arguments = str.Remove(0, nSecond + 1).Trim();
				}
			}

			if(applicationPath == null)
			{
				int nSpace = str.IndexOf(' ');

				if(nSpace >= 0)
				{
					applicationPath = str.Substring(0, nSpace);
                    arguments = str.Remove(0, nSpace).Trim();
				}
				else applicationPath = strCmdLine;
			}

		    if (arguments == null)
		    {
		        arguments = string.Empty;
		    }
		}

		public static bool TryParseUShort(string str, out ushort u)
		{
			return ushort.TryParse(str, out u);
		}

		public static bool TryParseInt(string str, out int n)
		{
			return int.TryParse(str, out n);
		}

		public static bool TryParseIntInvariant(string str, out int n)
		{
		    return int.TryParse(str, NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out n);
		}

		public static bool TryParseUInt(string str, out uint u)
		{
			return uint.TryParse(str, out u);
		}

		public static bool TryParseUIntInvariant(string str, out uint u)
		{
		    try
		    {
		        return uint.TryParse(str, NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out u);
		    }
		    catch (Exception)
		    {
		        u = 0;
		    }
		    return false;
		}

		public static bool TryParseLong(string str, out long n)
		{
#if !KeePassLibSD
			return long.TryParse(str, out n);
#else
			try { n = long.Parse(str); return true; }
			catch(Exception) { n = 0; }
			return false;
#endif
		}

		public static bool TryParseLongInvariant(string str, out long n)
		{
#if !KeePassLibSD
			return long.TryParse(str, NumberStyles.Integer,
				NumberFormatInfo.InvariantInfo, out n);
#else
			try
			{
				n = long.Parse(str, NumberStyles.Integer,
					NumberFormatInfo.InvariantInfo);
				return true;
			}
			catch(Exception) { n = 0; }
			return false;
#endif
		}

		public static bool TryParseULong(string str, out ulong u)
		{
#if !KeePassLibSD
			return ulong.TryParse(str, out u);
#else
			try { u = ulong.Parse(str); return true; }
			catch(Exception) { u = 0; }
			return false;
#endif
		}

		public static bool TryParseULongInvariant(string str, out ulong u)
		{
#if !KeePassLibSD
			return ulong.TryParse(str, NumberStyles.Integer,
				NumberFormatInfo.InvariantInfo, out u);
#else
			try
			{
				u = ulong.Parse(str, NumberStyles.Integer,
					NumberFormatInfo.InvariantInfo);
				return true;
			}
			catch(Exception) { u = 0; }
			return false;
#endif
		}

		public static bool TryParseDateTime(string str, out DateTime dt)
		{
#if !KeePassLibSD
			return DateTime.TryParse(str, out dt);
#else
			try { dt = DateTime.Parse(str); return true; }
			catch(Exception) { dt = DateTime.MinValue; return false; }
#endif
		}

		public static string CompactString3Dots(string strText, int nMaxChars)
		{
			Debug.Assert(strText != null);
			if(strText == null) throw new ArgumentNullException("strText");
			Debug.Assert(nMaxChars >= 0);
			if(nMaxChars < 0) throw new ArgumentOutOfRangeException("nMaxChars");

			if(nMaxChars == 0) return string.Empty;
			if(strText.Length <= nMaxChars) return strText;

			if(nMaxChars <= 3) return strText.Substring(0, nMaxChars);

			return strText.Substring(0, nMaxChars - 3) + "...";
		}

		public static string GetStringBetween(string strText, int nStartIndex,
			string strStart, string strEnd)
		{
			int nTemp;
			return GetStringBetween(strText, nStartIndex, strStart, strEnd, out nTemp);
		}

		public static string GetStringBetween(string strText, int nStartIndex,
			string strStart, string strEnd, out int innerStartIndex)
		{
		    if (strText == null)
		    {
		        throw new ArgumentNullException("strText");
		    }
		    if (strStart == null)
		    {
		        throw new ArgumentNullException("strStart");
		    }
		    if (strEnd == null)
		    {
		        throw new ArgumentNullException("strEnd");
		    }

			innerStartIndex = -1;

			var index = strText.IndexOf(strStart, nStartIndex, StringComparison.InvariantCultureIgnoreCase);
		    if (index < 0)
		    {
		        return string.Empty;
		    }

            index += strStart.Length;

            var endIndex = strText.IndexOf(strEnd, index, StringComparison.InvariantCultureIgnoreCase);
		    if (endIndex < 0)
		    {
		        return string.Empty;
		    }

            innerStartIndex = index;
            return strText.Substring(index, endIndex - index);
		}

		/// <summary>
		/// Removes all characters that are not valid XML characters,
		/// according to http://www.w3.org/TR/xml/#charsets .
		/// </summary>
		/// <param name="strText">Source text.</param>
		/// <returns>Text containing only valid XML characters.</returns>
		public static string SafeXmlString(string strText)
		{
			Debug.Assert(strText != null); // No throw
			if(string.IsNullOrEmpty(strText)) return strText;

			int nLength = strText.Length;
			StringBuilder sb = new StringBuilder(nLength);

			for(int i = 0; i < nLength; ++i)
			{
				char ch = strText[i];

				if(((ch >= '\u0020') && (ch <= '\uD7FF')) ||
					(ch == '\u0009') || (ch == '\u000A') || (ch == '\u000D') ||
					((ch >= '\uE000') && (ch <= '\uFFFD')))
					sb.Append(ch);
				else if((ch >= '\uD800') && (ch <= '\uDBFF')) // High surrogate
				{
					if((i + 1) < nLength)
					{
						var chLow = strText[i + 1];
						if((chLow >= '\uDC00') && (chLow <= '\uDFFF')) // Low sur.
						{
							sb.Append(ch);
							sb.Append(chLow);
							++i;
						}
						else { Debug.Assert(false); } // Low sur. invalid
					}
					else { Debug.Assert(false); } // Low sur. missing
				}

				Debug.Assert((ch < '\uDC00') || (ch > '\uDFFF')); // Lonely low sur.
			}

			return sb.ToString();
		}

        private static readonly Regex NaturalSplitRegEx = new Regex(@"([0-9]+)", RegexOptions.Compiled);
		public static int CompareNaturally(string strX, string strY)
		{
			Debug.Assert(strX != null);
			if(strX == null) throw new ArgumentNullException("strX");
			Debug.Assert(strY != null);
			if(strY == null) throw new ArgumentNullException("strY");

			if(NativeMethods.SupportsStrCmpNaturally)
				return NativeMethods.StrCmpNaturally(strX, strY);

			strX = strX.ToLower(); // Case-insensitive comparison
			strY = strY.ToLower();

			var partsX = NaturalSplitRegEx.Split(strX);
			var partsY = NaturalSplitRegEx.Split(strY);

			for(var i = 0; i < Math.Min(partsX.Length, partsY.Length); ++i)
			{
				string strPartX = partsX[i], strPartY = partsY[i];
				int iPartCompare;

				ulong uX, uY;
			    if (ulong.TryParse(strPartX, out uX) && ulong.TryParse(strPartY, out uY))
			    {
			        iPartCompare = uX.CompareTo(uY);
			    }
			    else
			    {
			        iPartCompare = String.Compare(strPartX, strPartY, StringComparison.Ordinal);
			    }

			    if (iPartCompare != 0)
			    {
			        return iPartCompare;
			    }
			}

		    if (partsX.Length == partsY.Length)
		    {
		        return 0;
		    }

		    if (partsX.Length < partsY.Length)
		    {
		        return -1;
		    }

			return 1;
		}

		public static string RemoveAccelerator(string menuText)
		{
		    if (menuText == null)
		    {
                throw new ArgumentNullException("menuText");
		    }

			var str = menuText;

			for(var character = 'A'; character <= 'Z'; ++character)
			{
				var strEnhAcc = @"(&" + character.ToString() + @")";
				if (str.IndexOf(strEnhAcc, StringComparison.InvariantCultureIgnoreCase) >= 0)
				{
					str = str.Replace(@" " + strEnhAcc, string.Empty);
					str = str.Replace(strEnhAcc, string.Empty);
				}
			}

			str = str.Replace(@"&", string.Empty);

			return str;
		}

		public static string AddAccelerator(string menuText, List<char> availKeys)
		{
		    if (menuText == null)
		    {
		        return null;
		    }

		    if (availKeys == null)
		    {
		        return menuText;
		    }

		    var xa = -1;
            var xs = 0;
		    var index = 0;
			foreach (var character in menuText)
			{
				var upperCaseChar = char.ToUpperInvariant(character);
				xa = availKeys.IndexOf(upperCaseChar);
			    if (xa >= 0)
			    {
			        xs = index;
			        break;
			    }

			    var lowerCaseChar = char.ToLowerInvariant(character);
				xa = availKeys.IndexOf(lowerCaseChar);
			    if (xa >= 0)
			    {
			        xs = index;
			        break;
			    }

			    index ++;
			}

		    if (xa < 0)
		    {
		        return menuText;
		    }

			availKeys.RemoveAt(xa);
			return menuText.Insert(xs, @"&");
		}

		public static string EncodeMenuText(string strText)
		{
			if(strText == null) throw new ArgumentNullException("strText");

			return strText.Replace(@"&", @"&&");
		}

		public static string EncodeToolTipText(string strText)
		{
			if(strText == null) throw new ArgumentNullException("strText");

			return strText.Replace(@"&", @"&&&");
		}

		public static bool IsHexString(string hexString, bool strict)
		{
		    if (hexString == null)
		    {
		        throw new ArgumentNullException("hexString");
		    }

		    if (hexString.Length == 0)
		    {
		        return true;
		    }

			foreach(var character in hexString)
			{
				if((character >= '0') && (character <= '9')) continue;
				if((character >= 'a') && (character <= 'z')) continue;
				if((character >= 'A') && (character <= 'Z')) continue;

				if(strict) return false;

				if((character == ' ') || (character == '\t') || (character == '\r') || (character == '\n'))
					continue;

				return false;
			}

			return true;
		}

		private static readonly char[] PatternPartsSeparator = { '*' };
		public static bool SimplePatternMatch(string strPattern, string strText, StringComparison sc)
		{
			if(strPattern == null) throw new ArgumentNullException("strPattern");
			if(strText == null) throw new ArgumentNullException("strText");

			if(strPattern.IndexOf('*') < 0) return strText.Equals(strPattern, sc);

			var patternParts = strPattern.Split(PatternPartsSeparator, StringSplitOptions.RemoveEmptyEntries);
		    if (patternParts.Length == 0)
		    {
		        return true;
		    }

		    if (strText.Length == 0)
		    {
		        return false;
		    }

			if(!strPattern.StartsWith(@"*") && !strText.StartsWith(patternParts[0], sc))
			{
				return false;
			}

			if(!strPattern.EndsWith(@"*") && !strText.EndsWith(patternParts[patternParts.Length - 1], sc))
			{
				return false;
			}

			var offset = 0;
			for(var i = 0; i < patternParts.Length; ++i)
			{
				var strPart = patternParts[i];

				var indexFound = strText.IndexOf(strPart, offset, sc);
			    if (indexFound < offset)
			    {
			        return false;
			    }

				offset = indexFound + strPart.Length;
			    if (offset == strText.Length)
			    {
			        return (i == (patternParts.Length - 1));
			    }
			}

			return true;
		}

		public static bool StringToBool(string str)
		{
			if(string.IsNullOrEmpty(str)) return false; // No assert

			string s = str.Trim().ToLower();
			if(s == "true") return true;
			if(s == "yes") return true;
			if(s == "1") return true;
			if(s == "enabled") return true;
			if(s == "checked") return true;

			return false;
		}

		public static bool? StringToBoolEx(string str)
		{
			if(string.IsNullOrEmpty(str)) return null;

			string s = str.Trim().ToLower();
			if(s == "true") return true;
			if(s == "false") return false;

			return null;
		}

		public static string BoolToString(bool bValue)
		{
			return (bValue ? "true" : "false");
		}

		public static string BoolToStringEx(bool? bValue)
		{
			if(bValue.HasValue) return BoolToString(bValue.Value);
			return "null";
		}

		/// <summary>
		/// Normalize new line characters in a string. Input strings may
		/// contain mixed new line character sequences from all commonly
		/// used operating systems (i.e. \r\n from Windows, \n from Unix
		/// and \r from Mac OS.
		/// </summary>
		/// <param name="str">String with mixed new line characters.</param>
		/// <param name="bWindows">If <c>true</c>, new line characters
		/// are normalized for Windows (\r\n); if <c>false</c>, new line
		/// characters are normalized for Unix (\n).</param>
		/// <returns>String with normalized new line characters.</returns>
		public static string NormalizeNewLines(string str, bool bWindows)
		{
			if(string.IsNullOrEmpty(str)) return str;

			str = str.Replace("\r\n", "\n");
			str = str.Replace("\r", "\n");

			if(bWindows) str = str.Replace("\n", "\r\n");

			return str;
		}

		private static char[] newLineChars;
		public static void NormalizeNewLines(Dictionary<string, ProtectedString> dict, bool isWindows)
		{
		    if (dict == null)
		    {
		        return;
		    }

		    if (newLineChars == null)
		    {
		        newLineChars = new []{ '\r', '\n' };
		    }

			var keys = dict.Keys.ToList();
		    foreach (var strKey in keys)
		    {
		        var protectedString = dict[strKey];
		        if (protectedString == null)
		        {
		            continue;
		        }

		        var value = protectedString.ReadString();
		        if (value.IndexOfAny(newLineChars) < 0)
		        {
		            continue;
		        }

		        dict[strKey] = new ProtectedString(protectedString.IsProtected, NormalizeNewLines(value, isWindows));
		    }
		}

		public static string GetNewLineSeq(string stringToTest)
		{
		    if (stringToTest == null)
		    {
		        return Environment.NewLine;
		    }

		    var nLf = 0;
		    var nCr = 0; 
            var nCrLf = 0;
			var chLast = char.MinValue;
			foreach (var character in stringToTest)
			{
			    if (character == '\r')
			    {
			        ++nCr;
			    }
                else if (character == '\n')
				{
					++nLf;
				    if (chLast == '\r')
				    {
				        ++nCrLf;
				    }
				}

                chLast = character;
			}

			nCr -= nCrLf;
			nLf -= nCrLf;

			var nMax = Math.Max(nCrLf, Math.Max(nCr, nLf));
		    if (nMax == 0)
		    {
		        return Environment.NewLine;
		    }

			if(nCrLf == nMax) return "\r\n";
			return ((nLf == nMax) ? "\n" : "\r");
		}

		public static string AlphaNumericOnly(string stringToTest)
		{
			if(string.IsNullOrEmpty(stringToTest)) return stringToTest;

			var sb = new StringBuilder();
		    foreach (var character in stringToTest)
		    {
		        if (((character >= 'a') && (character <= 'z')) ||
		            ((character >= 'A') && (character <= 'Z')) ||
		            ((character >= '0') && (character <= '9')))
		        {
		            sb.Append(character);
		        }
		    }

		    return sb.ToString();
		}

		public static string FormatDataSize(ulong uBytes)
		{
			const ulong uKb = 1024;
			const ulong uMb = uKb * uKb;
			const ulong uGb = uMb * uKb;
			const ulong uTb = uGb * uKb;

		    if (uBytes == 0)
		    {
		        return "0 KB";
		    }

		    if (uBytes <= uKb)
		    {
		        return "1 KB";
		    }

		    if (uBytes <= uMb)
		    {
		        return (((uBytes - 1UL) / uKb) + 1UL) + " KB";
		    }

		    if (uBytes <= uGb)
		    {
		        return (((uBytes - 1UL) / uMb) + 1UL) + " MB";
		    }

		    if (uBytes <= uTb)
		    {
		        return (((uBytes - 1UL) / uGb) + 1UL) + " GB";
		    }

			return (((uBytes - 1UL)/ uTb) + 1UL) + " TB";
		}

		public static string FormatDataSizeKb(ulong uBytes)
		{
			const ulong uKb = 1024;

		    if (uBytes == 0)
		    {
		        return "0 KB";
		    }

		    if (uBytes <= uKb)
		    {
		        return "1 KB";
		    }
			
			return (((uBytes - 1UL) / uKb) + 1UL) + " KB";
		}

		private static readonly char[] VersionSep = { '.', ',' };

	    public static ulong ParseVersion(string strVersion)
	    {
	        if (strVersion == null)
	        {
	            return 0;
	        }

	        var versions = strVersion.Split(VersionSep);
	        if ((versions.Length == 0))
	        {
	            return 0;
	        }

	        ushort uPart;
	        TryParseUShort(versions[0].Trim(), out uPart);
	        var uVer = ((ulong) uPart << 48);

	        if (versions.Length >= 2)
	        {
	            TryParseUShort(versions[1].Trim(), out uPart);
	            uVer |= ((ulong) uPart << 32);
	        }

	        if (versions.Length >= 3)
	        {
	            TryParseUShort(versions[2].Trim(), out uPart);
	            uVer |= ((ulong) uPart << 16);
	        }

	        if (versions.Length >= 4)
	        {
	            TryParseUShort(versions[3].Trim(), out uPart);
	            uVer |= uPart;
	        }

	        return uVer;
	    }

	    public static string VersionToString(ulong uVersion)
		{
			return VersionToString(uVersion, 1U);
		}

		[Obsolete]
		public static string VersionToString(ulong uVersion,
			bool bEnsureAtLeastTwoComp)
		{
			return VersionToString(uVersion, (bEnsureAtLeastTwoComp ? 2U : 1U));
		}

		public static string VersionToString(ulong uVersion, uint uMinComp)
		{
			StringBuilder sb = new StringBuilder();
			uint uComp = 0;

			for(int i = 0; i < 4; ++i)
			{
				if(uVersion == 0UL) break;

				ushort us = (ushort)(uVersion >> 48);

				if(sb.Length > 0) sb.Append('.');

				sb.Append(us.ToString(NumberFormatInfo.InvariantInfo));
				++uComp;

				uVersion <<= 16;
			}

			while(uComp < uMinComp)
			{
				if(sb.Length > 0) sb.Append('.');

				sb.Append('0');
				++uComp;
			}

			return sb.ToString();
		}

		private static readonly byte[] EntropyOptions = { 0xA5, 0x74, 0x2E, 0xEC };

		public static string EncryptString(string strPlainText)
		{
			if(string.IsNullOrEmpty(strPlainText)) return string.Empty;

		    try
		    {
		        var plainBytes = Utf8.GetBytes(strPlainText);
                var encryptedBytes = ProtectedData.Protect(plainBytes, EntropyOptions, DataProtectionScope.CurrentUser);

		        return Convert.ToBase64String(encryptedBytes, Base64FormattingOptions.None);
		    }
		    catch (Exception)
		    {
		        Debug.Assert(false);
		    }

			return strPlainText;
		}

		public static string DecryptString(string cipherText)
		{
            if (string.IsNullOrEmpty(cipherText)) return string.Empty;

		    try
		    {
                var encryptedValue = Convert.FromBase64String(cipherText);
                var plainValue = ProtectedData.Unprotect(encryptedValue, EntropyOptions, DataProtectionScope.CurrentUser);

		        return Utf8.GetString(plainValue, 0, plainValue.Length);
		    }
		    catch (Exception)
		    {
		        Debug.Assert(false);
		    }

            return cipherText;
		}

		public static string SerializeIntArray(int[] numbers)
		{
		    if (numbers == null)
		    {
		        throw new ArgumentNullException("numbers");
		    }

			var sb = new StringBuilder();
            for (var i = 0; i < numbers.Length; ++i)
			{
			    if (i > 0)
			    {
			        sb.Append(' ');
			    }
                sb.Append(numbers[i].ToString(NumberFormatInfo.InvariantInfo));
			}

			return sb.ToString();
		}

		public static int[] DeserializeIntArray(string strSerialized)
		{
		    if (strSerialized == null)
		    {
		        throw new ArgumentNullException("strSerialized");
		    }

		    if (strSerialized.Length == 0)
		    {
		        return new int[0];
		    }

			var stringParts = strSerialized.Split(' ');
			var value = new int[stringParts.Length];

			for(var i = 0; i < stringParts.Length; ++i)
			{
				int n;
				if(!TryParseIntInvariant(stringParts[i], out n)) { Debug.Assert(false); }
				value[i] = n;
			}

			return value;
		}

		private static readonly char[] TagSeparator = { ',', ';', ':' };
		public static string TagsToString(List<string> tags, bool forDisplay)
		{
			if(tags == null) throw new ArgumentNullException("tags");

			var sb = new StringBuilder();
			var first = true;

			foreach(var stringTag in tags)
			{
			    if (string.IsNullOrEmpty(stringTag))
			    {
			        continue;
			    }

				if(!first)
				{
					if(forDisplay) sb.Append(", ");
					else sb.Append(';');
				}

				sb.Append(stringTag);

				first = false;
			}

			return sb.ToString();
		}

		public static List<string> StringToTags(string strTags)
		{
		    if (strTags == null)
		    {
		        throw new ArgumentNullException("strTags");
		    }

			var tagList = new List<string>();
			if(strTags.Length == 0) return tagList;

            var tags = strTags.Split(TagSeparator);
		    tagList.AddRange(tags.Select(strTag => strTag.Trim()).Where(strFlt => strFlt.Length > 0));

		    return tagList;
		}

		public static string Obfuscate(string strPlain)
		{
		    if (strPlain == null)
		    {
                return string.Empty;
		    }

		    if (strPlain.Length == 0)
		    {
		        return string.Empty;
		    }

			var passwordBytes = Utf8.GetBytes(strPlain);

			Array.Reverse(passwordBytes);
		    for (var i = 0; i < passwordBytes.Length; ++i)
		    {
		        passwordBytes[i] = (byte)(passwordBytes[i] ^ 0x65);
		    }

			return Convert.ToBase64String(passwordBytes, Base64FormattingOptions.None);
		}

		public static string Deobfuscate(string strObf)
		{
		    if (strObf == null)
		    {
                return string.Empty;
		    }

		    if (strObf.Length == 0)
		    {
		        return string.Empty;
		    }

		    try
		    {
		        var passwordBytes = Convert.FromBase64String(strObf);

		        for (var i = 0; i < passwordBytes.Length; ++i)
		        {
		            passwordBytes[i] = (byte) (passwordBytes[i] ^ 0x65);
		        }

		        Array.Reverse(passwordBytes);

		        return Utf8.GetString(passwordBytes, 0, passwordBytes.Length);
		    }

		    catch (Exception)
		    {
		        Debug.Assert(false);
		    }

			return string.Empty;
		}

		/// <summary>
		/// Split a string and include the separators in the splitted array.
		/// </summary>
		/// <param name="stringToSplit">String to split.</param>
		/// <param name="seaparators">Separators.</param>
		/// <param name="caseSensitive">Specifies whether separators are
		/// matched case-sensitively or not.</param>
		/// <returns>Splitted string including separators.</returns>
		public static List<string> SplitWithSep(string stringToSplit, string[] seaparators, bool caseSensitive)
		{
		    if (stringToSplit == null)
		    {
                throw new ArgumentNullException("stringToSplit");
		    }

		    if (seaparators == null)
		    {
                throw new ArgumentNullException("seaparators");
		    }

			var valueList = new List<string>();
			while(true)
			{
				int minIndex = int.MaxValue, minSep = -1;
				for(int i = 0; i < seaparators.Length; ++i)
				{
					var strSep = seaparators[i];
				    if (string.IsNullOrEmpty(strSep))
				    {
				        continue;
				    }

					int iIndex = (caseSensitive ? stringToSplit.IndexOf(strSep) :
						stringToSplit.IndexOf(strSep, StrUtil.CaseIgnoreCmp));
					if((iIndex >= 0) && (iIndex < minIndex))
					{
						minIndex = iIndex;
						minSep = i;
					}
				}

				if(minIndex == int.MaxValue) break;

				valueList.Add(stringToSplit.Substring(0, minIndex));
				valueList.Add(seaparators[minSep]);

				stringToSplit = stringToSplit.Substring(minIndex + seaparators[minSep].Length);
			}

			valueList.Add(stringToSplit);
			return valueList;
		}

		public static string MultiToSingleLine(string strMulti)
		{
			if(strMulti == null) { Debug.Assert(false); return string.Empty; }
			if(strMulti.Length == 0) return string.Empty;

			string str = strMulti;
			str = str.Replace("\r\n", " ");
			str = str.Replace("\r", " ");
			str = str.Replace("\n", " ");

			return str;
		}

		public static List<string> SplitSearchTerms(string strSearch)
		{
			var stringList = new List<string>();
		    if (strSearch == null)
		    {
		        Debug.Assert(false);
		        return stringList;
		    }

		    var term = new StringBuilder();
			var quoted = false;

			foreach(var character in strSearch)
			{
				if(((character == ' ') || (character == '\t') || (character == '\r') ||
					(character == '\n')) && !quoted)
				{
					if(term.Length > 0) stringList.Add(term.ToString());

					term.Remove(0, term.Length);
				}
				else if (character == '\"')
				{
				    quoted = !quoted;
				}
				else
				{
				    term.Append(character);
				}
			}

		    if (term.Length > 0)
		    {
		        stringList.Add(term.ToString());
		    }

			return stringList;
		}

		public static int CompareLengthGt(string x, string y)
		{
			if(x.Length == y.Length) return 0;
			return ((x.Length > y.Length) ? -1 : 1);
		}

		public static bool IsDataUri(string strUri)
		{
			return IsDataUri(strUri, null);
		}

		public static bool IsDataUri(string strUri, string strReqMimeType)
		{
			if(strUri == null) { Debug.Assert(false); return false; }
			// strReqMimeType may be null

			const string strPrefix = "data:";
			if(!strUri.StartsWith(strPrefix, StrUtil.CaseIgnoreCmp))
				return false;

			int iC = strUri.IndexOf(',');
			if(iC < 0) return false;

			if(!string.IsNullOrEmpty(strReqMimeType))
			{
				int iS = strUri.IndexOf(';', 0, iC);
				int iTerm = ((iS >= 0) ? iS : iC);

				string strMime = strUri.Substring(strPrefix.Length,
					iTerm - strPrefix.Length);
				if(!strMime.Equals(strReqMimeType, StrUtil.CaseIgnoreCmp))
					return false;
			}

			return true;
		}

		/// <summary>
		/// Create a data URI (according to RFC 2397).
		/// </summary>
		/// <param name="pbData">Data to encode.</param>
		/// <param name="strMimeType">Optional MIME type. If <c>null</c>,
		/// an appropriate type is used.</param>
		/// <returns>Data URI.</returns>
		public static string DataToDataUri(byte[] pbData, string strMimeType)
		{
			if(pbData == null) throw new ArgumentNullException("pbData");

			if(strMimeType == null) strMimeType = "application/octet-stream";

#if (!KeePassLibSD && !KeePassRT)
			return ("data:" + strMimeType + ";base64," + Convert.ToBase64String(
				pbData, Base64FormattingOptions.None));
#else
			return ("data:" + strMimeType + ";base64," + Convert.ToBase64String(
				pbData));
#endif
		}

		/// <summary>
		/// Convert a data URI (according to RFC 2397) to binary data.
		/// </summary>
		/// <param name="strDataUri">Data URI to decode.</param>
		/// <returns>Decoded binary data.</returns>
		public static byte[] DataUriToData(string strDataUri)
		{
			if(strDataUri == null) throw new ArgumentNullException("strDataUri");
			if(!strDataUri.StartsWith("data:", StrUtil.CaseIgnoreCmp)) return null;

			int iSep = strDataUri.IndexOf(',');
			if(iSep < 0) return null;

			string strDesc = strDataUri.Substring(5, iSep - 5);
			bool bBase64 = strDesc.EndsWith(";base64", StrUtil.CaseIgnoreCmp);

			string strData = strDataUri.Substring(iSep + 1);

			if(bBase64) return Convert.FromBase64String(strData);

			MemoryStream ms = new MemoryStream();

#if KeePassRT
			Encoding enc = StrUtil.Utf8;
#else
			Encoding enc = Encoding.ASCII;
#endif

			string[] v = strData.Split('%');
			byte[] pb = enc.GetBytes(v[0]);
			ms.Write(pb, 0, pb.Length);
			for(int i = 1; i < v.Length; ++i)
			{
				ms.WriteByte(Convert.ToByte(v[i].Substring(0, 2), 16));
				pb = enc.GetBytes(v[i].Substring(2));
				ms.Write(pb, 0, pb.Length);
			}

			pb = ms.ToArray();
			ms.Close();
			return pb;
		}

		/// <summary>
		/// Remove placeholders from a string (wrapped in '{' and '}').
		/// This doesn't remove environment variables (wrapped in '%').
		/// </summary>
		public static string RemovePlaceholders(string str)
		{
			if(str == null) { Debug.Assert(false); return string.Empty; }

			while(true)
			{
				int iPlhStart = str.IndexOf('{');
				if(iPlhStart < 0) break;

				int iPlhEnd = str.IndexOf('}', iPlhStart); // '{' might be at end
				if(iPlhEnd < 0) break;

				str = (str.Substring(0, iPlhStart) + str.Substring(iPlhEnd + 1));
			}

			return str;
		}

		public static StrEncodingInfo GetEncoding(StrEncodingType t)
		{
			foreach(StrEncodingInfo sei in StrUtil.Encodings)
			{
				if(sei.Type == t) return sei;
			}

			return null;
		}

		public static StrEncodingInfo GetEncoding(string strName)
		{
			foreach(StrEncodingInfo sei in StrUtil.Encodings)
			{
				if(sei.Name == strName) return sei;
			}

			return null;
		}

		private static string allCharacters;

	    /// <summary>
	    /// Find a character that does not occur within a given text.
	    /// </summary>
	    public static char GetUnusedChar(string strText)
	    {
	        if (strText == null)
	        {
	            return '@';
	        }

	        var character = char.MinValue;
	        if (allCharacters == null)
	        {
	            allCharacters = PwCharSet.PrintableAsciiSpecial + PwCharSet.UpperCase +
	                            PwCharSet.LowerCase + PwCharSet.Digits + PwCharSet.PrintableAsciiSpecial;
	        }

	        foreach (var ch in allCharacters)
	        {
	            if (strText.IndexOf(ch) < 0)
	            {
	                character = ch;
	            }
	        }

	        return character;
	    }

	    public static char ByteToSafeChar(byte bt)
		{
			const char chDefault = '.';

			// 00-1F are C0 control chars
			if(bt < 0x20) return chDefault;

			// 20-7F are basic Latin; 7F is DEL
			if(bt < 0x7F) return (char)bt;

			// 80-9F are C1 control chars
			if(bt < 0xA0) return chDefault;

			// A0-FF are Latin-1 supplement; AD is soft hyphen
			if(bt == 0xAD) return '-';
			return (char)bt;
		}

		public static int Count(string str, string strNeedle)
		{
			if(str == null) { Debug.Assert(false); return 0; }
			if(string.IsNullOrEmpty(strNeedle)) { Debug.Assert(false); return 0; }

			int iOffset = 0, iCount = 0;
			while(iOffset < str.Length)
			{
				int p = str.IndexOf(strNeedle, iOffset);
				if(p < 0) break;

				++iCount;
				iOffset = p + 1;
			}

			return iCount;
		}
	}
}
