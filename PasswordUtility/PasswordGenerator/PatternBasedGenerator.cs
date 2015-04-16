using System;
using System.Collections.Generic;
using System.Diagnostics;
using PasswordUtility.Security;

namespace PasswordUtility.PasswordGenerator
{
	internal static class PatternBasedGenerator
	{
		internal static PwgError Generate(out ProtectedString psOut,
			PwProfile pwProfile, CryptoRandomStream crsRandomSource)
		{
			psOut = ProtectedString.Empty;
			LinkedList<char> vGenerated = new LinkedList<char>();
			PwCharSet pcsCurrent = new PwCharSet();
			PwCharSet pcsCustom = new PwCharSet();
			PwCharSet pcsUsed = new PwCharSet();
			bool bInCharSetDef = false;

			string strPattern = ExpandPattern(pwProfile.Pattern);
			if(strPattern.Length == 0) return PwgError.Success;

			CharStream csStream = new CharStream(strPattern);
			char ch = csStream.ReadChar();

			while(ch != char.MinValue)
			{
				pcsCurrent.Clear();

				bool bGenerateChar = false;

				if(ch == '\\')
				{
					ch = csStream.ReadChar();
					if(ch == char.MinValue) // Backslash at the end
					{
						vGenerated.AddLast('\\');
						break;
					}

					if(bInCharSetDef) pcsCustom.Add(ch);
					else
					{
						vGenerated.AddLast(ch);
						pcsUsed.Add(ch);
					}
				}
				else if(ch == '^')
				{
					ch = csStream.ReadChar();
					if(ch == char.MinValue) // ^ at the end
					{
						vGenerated.AddLast('^');
						break;
					}

					if(bInCharSetDef) pcsCustom.Remove(ch);
				}
				else if(ch == '[')
				{
					pcsCustom.Clear();
					bInCharSetDef = true;
				}
				else if(ch == ']')
				{
					pcsCurrent.Add(pcsCustom.ToString());

					bInCharSetDef = false;
					bGenerateChar = true;
				}
				else if(bInCharSetDef)
				{
					if(pcsCustom.AddCharSet(ch) == false)
						pcsCustom.Add(ch);
				}
				else if(pcsCurrent.AddCharSet(ch) == false)
				{
					vGenerated.AddLast(ch);
					pcsUsed.Add(ch);
				}
				else bGenerateChar = true;

				if(bGenerateChar)
				{
					PwGenerator.PrepareCharSet(pcsCurrent, pwProfile);

					if(pwProfile.NoRepeatingCharacters)
						pcsCurrent.Remove(pcsUsed.ToString());

					char chGen = PwGenerator.GenerateCharacter(pwProfile,
						pcsCurrent, crsRandomSource);

					if(chGen == char.MinValue) return PwgError.TooFewCharacters;

					vGenerated.AddLast(chGen);
					pcsUsed.Add(chGen);
				}

				ch = csStream.ReadChar();
			}

			if(vGenerated.Count == 0) return PwgError.Success;

			char[] vArray = new char[vGenerated.Count];
			vGenerated.CopyTo(vArray, 0);

			if(pwProfile.PatternPermutePassword)
				PwGenerator.ShufflePassword(vArray, crsRandomSource);

			byte[] pbUtf8 = StrUtil.Utf8.GetBytes(vArray);
			psOut = new ProtectedString(true, pbUtf8);
			MemUtil.ZeroByteArray(pbUtf8);
			Array.Clear(vArray, 0, vArray.Length);
			vGenerated.Clear();

			return PwgError.Success;
		}

		private static string ExpandPattern(string strPattern)
		{
			Debug.Assert(strPattern != null); if(strPattern == null) return string.Empty;
			string str = strPattern;

			while(true)
			{
				int nOpen = FindFirstUnescapedChar(str, '{');
				int nClose = FindFirstUnescapedChar(str, '}');

				if((nOpen >= 0) && (nOpen < nClose))
				{
					string strCount = str.Substring(nOpen + 1, nClose - nOpen - 1);
					str = str.Remove(nOpen, nClose - nOpen + 1);

					uint uRepeat;
					if(StrUtil.TryParseUInt(strCount, out uRepeat) && (nOpen >= 1))
					{
						if(uRepeat == 0)
							str = str.Remove(nOpen - 1, 1);
						else
							str = str.Insert(nOpen, new string(str[nOpen - 1], (int)uRepeat - 1));
					}
				}
				else break;
			}

			return str;
		}

		private static int FindFirstUnescapedChar(string str, char ch)
		{
			for(int i = 0; i < str.Length; ++i)
			{
				char chCur = str[i];

				if(chCur == '\\') ++i; // Next is escaped, skip it
				else if(chCur == ch) return i;
			}

			return -1;
		}
	}
}
