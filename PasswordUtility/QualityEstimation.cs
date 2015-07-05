using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Linq;
using PasswordUtility.PasswordGenerator;

namespace PasswordUtility
{
	/// <summary>
	/// A class that offers static functions to estimate the quality of
	/// passwords.
	/// </summary>
	public static class QualityEstimation
	{
		private static class PatternId
		{
			public const char LowerAlpha = 'L';
			public const char UpperAlpha = 'U';
			public const char Digit = 'D';
			public const char Special = 'S';
			public const char High = 'H';
			public const char Other = 'X';

			public const char Dictionary = 'W';
			public const char Repetition = 'R';
			public const char Number = 'N';
			public const char DiffSeq = 'C';

			public const string All = "LUDSHXWRNC";
		}

		private sealed class QeCharType
		{
			private readonly char typeId;
			public char TypeId { get { return typeId; } }

			private readonly string alphabetString;
			public string Alphabet { get { return alphabetString; } }

			private readonly int charNumber;
			public int CharCount { get { return charNumber; } }

			private readonly char firstCharacter;
			private readonly char lastCharacter;

			private readonly double characterSize;
			public double CharSize { get { return characterSize; } }

			public QeCharType(char charTypeId, string alphabet, bool isConsecutive)
			{
			    if (alphabet == null)
			    {
			        throw new ArgumentNullException();
			    }

			    if (alphabet.Length == 0)
			    {
			        throw new ArgumentException();
			    }

				typeId = charTypeId;
				alphabetString = alphabet;
				charNumber = alphabetString.Length;
				firstCharacter = (isConsecutive ? alphabetString[0] : char.MinValue);
				lastCharacter = (isConsecutive ? alphabetString[charNumber - 1] : char.MinValue);

				characterSize = Log2(charNumber);

				Debug.Assert(((lastCharacter - firstCharacter) == (charNumber - 1)) ||
					!isConsecutive);
			}

            public QeCharType(char charTypeId, int length) // Catch-none set
			{
                if (length <= 0)
                {
                    throw new ArgumentOutOfRangeException();
                }

				typeId = charTypeId;
				alphabetString = string.Empty;
				charNumber = length;
				firstCharacter = char.MinValue;
				lastCharacter = char.MinValue;

				characterSize = Log2(charNumber);
			}

			public bool Contains(char ch)
			{
			    if (lastCharacter != char.MinValue)
			    {
			        return ((ch >= firstCharacter) && (ch <= lastCharacter));
			    }

				Debug.Assert(alphabetString.Length > 0); // Don't call for catch-none set
				return (alphabetString.IndexOf(ch) >= 0);
			}
		}

		private sealed class EntropyEncoder
		{
			private readonly string alphabetString;
			private readonly Dictionary<char, ulong> characterHistory = new Dictionary<char, ulong>();
			private readonly ulong baseWeight;
			private readonly ulong charWeight;
			private readonly ulong occExclThreshold;

			public EntropyEncoder(string strAlphabet, ulong baseWeight,
				ulong charWeight, ulong occExclThreshold)
			{
			    if (strAlphabet == null)
			    {
			        throw new ArgumentNullException();
			    }

			    if (strAlphabet.Length == 0)
			    {
			        throw new ArgumentException();
			    }

				alphabetString = strAlphabet;
				this.baseWeight = baseWeight;
				this.charWeight = charWeight;
				this.occExclThreshold = occExclThreshold;

#if DEBUG
				var d = new Dictionary<char, bool>();
				foreach(var ch in alphabetString) { d[ch] = true; }
				Debug.Assert(d.Count == alphabetString.Length); // No duplicates
#endif
			}

			public void Reset()
			{
				characterHistory.Clear();
			}

			public void Write(char ch)
			{
				Debug.Assert(alphabetString.IndexOf(ch) >= 0);

				ulong uOcc;
				characterHistory.TryGetValue(ch, out uOcc);
				Debug.Assert(characterHistory.ContainsKey(ch) || (uOcc == 0));
				characterHistory[ch] = uOcc + 1;
			}

			public double GetOutputSize()
			{
				var totalWeight = baseWeight * (ulong)alphabetString.Length;
				foreach(var u in characterHistory.Values)
				{
					Debug.Assert(u >= 1);
					if(u > occExclThreshold)
                        totalWeight += (u - occExclThreshold) * charWeight;
				}

			    var dSize = 0.0;
                double localTotalWeight = totalWeight;
				foreach(var u in characterHistory.Values)
				{
					var uWeight = baseWeight;
				    if (u > occExclThreshold)
				    {
				        uWeight += (u - occExclThreshold) * charWeight;
				    }

                    dSize -= u * Log2(uWeight / localTotalWeight);
				}

				return dSize;
			}
		}

		private sealed class MultiEntropyEncoder
		{
			private readonly Dictionary<char, EntropyEncoder> encoders =
				new Dictionary<char, EntropyEncoder>();

			public MultiEntropyEncoder()
			{
			}

			public void AddEncoder(char typeId, EntropyEncoder ec)
			{
				if(ec == null) { Debug.Assert(false); return; }

				Debug.Assert(!encoders.ContainsKey(typeId));
				encoders[typeId] = ec;
			}

			public void Reset()
			{
				foreach(var ec in encoders.Values) { ec.Reset(); }
			}

			public bool Write(char typeId, char chData)
			{
				EntropyEncoder ec;
			    if (!encoders.TryGetValue(typeId, out ec))
			    {
			        return false;
			    }

				ec.Write(chData);
				return true;
			}

			public double GetOutputSize()
			{
			    return encoders.Values.Sum(encoder => encoder.GetOutputSize());
			}
		}

		private sealed class QePatternInstance
		{
			private readonly int position;
			public int Position { get { return position; } }

			private readonly int length;
			public int Length { get { return length; } }

			private readonly char patternId;
			public char ThePatternId { get { return patternId; } }

			private readonly double cost;
			public double Cost { get { return cost; } }

			private readonly QeCharType singleCharacterType;
			public QeCharType SingleCharType { get { return singleCharacterType; } }

			public QePatternInstance(int position, int length, char patternId, double cost)
			{
				this.position = position;
				this.length = length;
                this.patternId = patternId;
				this.cost = cost;
				singleCharacterType = null;
			}

			public QePatternInstance(int position, int length, QeCharType singleCharacter)
			{
				this.position = position;
				this.length = length;
				patternId = singleCharacter.TypeId;
                cost = singleCharacter.CharSize;
				singleCharacterType = singleCharacter;
			}
		}

		private sealed class QePathState
		{
			public readonly int Position;
			public readonly List<QePatternInstance> Path;

			public QePathState(int position, List<QePatternInstance> path)
			{
				Position = position;
				Path = path;
			}
		}

		private static readonly object ObjSyncInit = new object();
		private static List<QeCharType> charTypes = null;

		private static void EnsureInitialized()
		{
			lock(ObjSyncInit)
			{
				if (charTypes == null)
				{
					var strSpecial = PwCharSet.PrintableAsciiSpecial;
				    if (strSpecial.IndexOf(' ') >= 0)
				    {
				        Debug.Assert(false);
				    }
					else strSpecial = strSpecial + " ";

					var nSp = strSpecial.Length;
					var nHi = PwCharSet.HighAnsiChars.Length;

				    charTypes = new List<QeCharType>
				    {
				        new QeCharType(PatternId.LowerAlpha,
				            PwCharSet.LowerCase, true),
				        new QeCharType(PatternId.UpperAlpha,
				            PwCharSet.UpperCase, true),
				        new QeCharType(PatternId.Digit,
				            PwCharSet.Digits, true),
				        new QeCharType(PatternId.Special,
				            strSpecial, false),
				        new QeCharType(PatternId.High,
				            PwCharSet.HighAnsiChars, false),
				        new QeCharType(PatternId.Other,
				            0x10000 - (2*26) - 10 - nSp - nHi)
				    };

				}
			}
		}

		/// <summary>
		/// Estimate the quality of a password.
		/// </summary>
		/// <param name="vPasswordChars">Password to check.</param>
		/// <returns>Estimated bit-strength of the password.</returns>
		public static uint EstimatePasswordBits(char[] vPasswordChars)
		{
			if(vPasswordChars == null) { Debug.Assert(false); return 0; }
		    if (vPasswordChars.Length == 0)
		    {
		        return 0;
		    }

			EnsureInitialized();

			var n = vPasswordChars.Length;
			var vPatterns = new List<QePatternInstance>[n];
			for(var i = 0; i < n; ++i)
			{
				vPatterns[i] = new List<QePatternInstance>();
				var piChar = new QePatternInstance(i, 1, GetCharType(vPasswordChars[i]));
				vPatterns[i].Add(piChar);
			}

			FindRepetitions(vPasswordChars, vPatterns);
			FindNumbers(vPasswordChars, vPatterns);
			FindDiffSeqs(vPasswordChars, vPatterns);
			FindPopularPasswords(vPasswordChars, vPatterns);

			// Encoders must not be static, because the entropy estimation
			// may run concurrently in multiple threads and the encoders are
			// not read-only
			var ecPattern = new EntropyEncoder(PatternId.All, 0, 1, 0);
			var mcData = new MultiEntropyEncoder();
			for(var i = 0; i < (charTypes.Count - 1); ++i)
			{
				// Let m be the alphabet size. In order to ensure that two same
				// characters cost at least as much as a single character, for
				// the probability p and weight w of the character it must hold:
				//     -log(1/m) >= -2*log(p)
				// <=> log(1/m) <= log(p^2) <=> 1/m <= p^2 <=> p >= sqrt(1/m);
				//     sqrt(1/m) = (1+w)/(m+w)
				// <=> m+w = (1+w)*sqrt(m) <=> m+w = sqrt(m) + w*sqrt(m)
				// <=> w*(1-sqrt(m)) = sqrt(m) - m <=> w = (sqrt(m)-m)/(1-sqrt(m))
				// <=> w = (sqrt(m)-m)*(1+sqrt(m))/(1-m)
				// <=> w = (sqrt(m)-m+m-m*sqrt(m))/(1-m) <=> w = sqrt(m)
				var uw = (ulong)Math.Sqrt(charTypes[i].CharCount);

				mcData.AddEncoder(charTypes[i].TypeId, new EntropyEncoder(charTypes[i].Alphabet, 1, uw, 1));
			}

			var dblMinCost = (double)int.MaxValue;
			var tStart = Environment.TickCount;

			var sRec = new Stack<QePathState>();
			sRec.Push(new QePathState(0, new List<QePatternInstance>()));
			while(sRec.Count > 0)
			{
				var s = sRec.Pop();

				if(s.Position >= n)
				{
					Debug.Assert(s.Position == n);

					var dblCost = ComputePathCost(s.Path, vPasswordChars, ecPattern, mcData);
				    if (dblCost < dblMinCost)
				    {
				        dblMinCost = dblCost;
				    }
				}
				else
				{
					var lSubs = vPatterns[s.Position];
					for(var i = lSubs.Count - 1; i >= 0; --i)
					{
						var pi = lSubs[i];
						Debug.Assert(pi.Position == s.Position);
						Debug.Assert(pi.Length >= 1);

						var lNewPath = new List<QePatternInstance>(s.Path.Count + 1);
						lNewPath.AddRange(s.Path);
						lNewPath.Add(pi);
						Debug.Assert(lNewPath.Capacity == (s.Path.Count + 1));

						var sNew = new QePathState(s.Position + pi.Length, lNewPath);
						sRec.Push(sNew);
					}
				}
			}

			return (uint)Math.Ceiling(dblMinCost);
		}

		private static QeCharType GetCharType(char ch)
		{
			var charTypeCount = charTypes.Count;
            Debug.Assert((charTypeCount > 0) && (charTypes[charTypeCount - 1].CharCount > 256));

            for (int i = 0; i < (charTypeCount - 1); ++i)
			{
				if(charTypes[i].Contains(ch))
					return charTypes[i];
			}

            return charTypes[charTypeCount - 1];
		}

		private static double ComputePathCost(List<QePatternInstance> patternInstanceCollection,
			char[] password, EntropyEncoder ecPattern, MultiEntropyEncoder mcData)
		{
			ecPattern.Reset();
		    for (var i = 0; i < patternInstanceCollection.Count; ++i)
		    {
		        ecPattern.Write(patternInstanceCollection[i].ThePatternId);
		    }
			
            var dblPatternCost = ecPattern.GetOutputSize();

			mcData.Reset();
			var dblDataCost = 0.0;
			foreach(var parameterInstance in patternInstanceCollection)
			{
                QeCharType characterType = parameterInstance.SingleCharType;
				if(characterType != null)
				{
					var character = password[parameterInstance.Position];
				    if (!mcData.Write(characterType.TypeId, character))
				    {
				        dblDataCost += parameterInstance.Cost;
				    }
				}
				else dblDataCost += parameterInstance.Cost;
			}
			dblDataCost += mcData.GetOutputSize();

			return (dblPatternCost + dblDataCost);
		}

		private static void FindPopularPasswords(char[] password, List<QePatternInstance>[] patterns)
		{
			var passwordLength = password.Length;

			var lower = new char[passwordLength];
			var leet = new char[passwordLength];
			for(var index = 0; index < passwordLength; ++index)
			{
				var character = password[index];

				lower[index] = char.ToLower(character);
				leet[index] = char.ToLower(DecodeLeetChar(character));
			}

			var erased = default(char);
			Debug.Assert(erased == char.MinValue);

			var maximumLength = Math.Min(passwordLength, PopularPasswords.MaxLength);
			for(var subLength = maximumLength; subLength >= 3; --subLength)
			{
			    if (!PopularPasswords.ContainsLength(subLength))
			    {
			        continue;
			    }

				var substring = new char[subLength];

				for(var index = 0; index <= (passwordLength - subLength); ++index)
				{
				    if (Array.IndexOf(lower, erased, index, subLength) >= 0)
				    {
				        continue;
				    }

					Array.Copy(lower, index, substring, 0, subLength);
					if(!EvalAddPopularPasswordPattern(patterns, password, index, substring, 0.0))
					{
						Array.Copy(leet, index, substring, 0, subLength);
					    if (EvalAddPopularPasswordPattern(patterns, password, index, substring, 1.5))
					    {
					        Array.Clear(lower, index, subLength);
					        Debug.Assert(lower[index] == erased);
					    }
					}
					else
					{
						Array.Clear(lower, index, subLength);
						Debug.Assert(lower[index] == erased);
					}
				}
			}
		}

		private static bool EvalAddPopularPasswordPattern(List<QePatternInstance>[] vPatterns,
			char[] vPassword, int i, char[] vSub, double dblCostPerMod)
		{
			ulong uDictSize;
			if(!PopularPasswords.IsPopularPassword(vSub, out uDictSize))
				return false;

			int n = vSub.Length;
			int d = HammingDistribution(vSub, 0, vPassword, i, n);

			double dblCost = Log2((double)uDictSize);

			// dblCost += log2(n binom d)
			int k = Math.Min(d, n - d);
			for(int j = n; j > (n - k); --j)
				dblCost += Log2(j);
			for(int j = k; j >= 2; --j)
				dblCost -= Log2(j);

			dblCost += dblCostPerMod * (double)d;

			vPatterns[i].Add(new QePatternInstance(i, n, PatternId.Dictionary,
				dblCost));
			return true;
		}

		private static char DecodeLeetChar(char chLeet)
		{
			if((chLeet >= '\u00C0') && (chLeet <= '\u00C6')) return 'a';
			if((chLeet >= '\u00C8') && (chLeet <= '\u00CB')) return 'e';
			if((chLeet >= '\u00CC') && (chLeet <= '\u00CF')) return 'i';
			if((chLeet >= '\u00D2') && (chLeet <= '\u00D6')) return 'o';
			if((chLeet >= '\u00D9') && (chLeet <= '\u00DC')) return 'u';
			if((chLeet >= '\u00E0') && (chLeet <= '\u00E6')) return 'a';
			if((chLeet >= '\u00E8') && (chLeet <= '\u00EB')) return 'e';
			if((chLeet >= '\u00EC') && (chLeet <= '\u00EF')) return 'i';
			if((chLeet >= '\u00F2') && (chLeet <= '\u00F6')) return 'o';
			if((chLeet >= '\u00F9') && (chLeet <= '\u00FC')) return 'u';

			char ch;
			switch(chLeet)
			{
				case '4':
				case '@':
				case '?':
				case '^':
				case '\u00AA': ch = 'a'; break;
				case '8':
				case '\u00DF': ch = 'b'; break;
				case '(':
				case '{':
				case '[':
				case '<':
				case '\u00A2':
				case '\u00A9':
				case '\u00C7':
				case '\u00E7': ch = 'c'; break;
				case '\u00D0':
				case '\u00F0': ch = 'd'; break;
				case '3':
				case '\u20AC':
				case '&':
				case '\u00A3': ch = 'e'; break;
				case '6':
				case '9': ch = 'g'; break;
				case '#': ch = 'h'; break;
				case '1':
				case '!':
				case '|':
				case '\u00A1':
				case '\u00A6': ch = 'i'; break;
				case '\u00D1':
				case '\u00F1': ch = 'n'; break;
				case '0':
				case '*':
				case '\u00A4': // Currency
				case '\u00B0': // Degree
				case '\u00D8':
				case '\u00F8': ch = 'o'; break;
				case '\u00AE': ch = 'r'; break;
				case '$':
				case '5':
				case '\u00A7': ch = 's'; break;
				case '+':
				case '7': ch = 't'; break;
				case '\u00B5': ch = 'u'; break;
				case '%':
				case '\u00D7': ch = 'x'; break;
				case '\u00A5':
				case '\u00DD':
				case '\u00FD':
				case '\u00FF': ch = 'y'; break;
				case '2': ch = 'z'; break;
				default: ch = chLeet; break;
			}

			return ch;
		}

		private static int HammingDistribution(char[] password1, int offset1, char[] password2, int offset2, int length)
		{
			var distribution = 0;
			for(var index = 0; index < length; ++index)
			{
			    if (password1[offset1 + index] != password2[offset2 + index])
			    {
			        ++distribution;
			    }
			}

			return distribution;
		}

		private static void FindRepetitions(char[] password, IReadOnlyList<List<QePatternInstance>> patterns)
		{
			var passwordLength = password.Length;
            var character = new char[passwordLength];
            Array.Copy(password, character, passwordLength);

			var erasedCharacter = char.MaxValue;
            for (var m = (passwordLength / 2); m >= 3; --m)
			{
                for (var x1 = 0; x1 <= (passwordLength - (2 * m)); ++x1)
				{
					var foundRepetition = false;

                    for (var x2 = (x1 + m); x2 <= (passwordLength - m); ++x2)
					{
                        if (PartsEqual(character, x1, x2, m))
						{
							var dblCost = Log2(x1 + 1) + Log2(m);
							patterns[x2].Add(new QePatternInstance(x2, m,
								PatternId.Repetition, dblCost));

                            ErasePart(character, x2, m, ref erasedCharacter);
							foundRepetition = true;
						}
					}

                    if (foundRepetition) ErasePart(character, x1, m, ref erasedCharacter);
				}
			}
		}

		private static bool PartsEqual(char[] v, int x1, int x2, int nLength)
		{
			for(var i = 0; i < nLength; ++i)
			{
			    if (v[x1 + i] != v[x2 + i])
			    {
			        return false;
			    }
			}

			return true;
		}

		private static void ErasePart(char[] v, int i, int n, ref char chErased)
		{
			for(var j = 0; j < n; ++j)
			{
				v[i + j] = chErased;
				--chErased;
			}
		}

		private static void FindNumbers(char[] password,
			List<QePatternInstance>[] patterns)
		{
			var passwordLength = password.Length;
			var sb = new StringBuilder();
			for(var i = 0; i < passwordLength; ++i)
			{
				var character = password[i];

			    if ((character >= '0') && (character <= '9'))
			    {
			        sb.Append(character);
			    }
				else
				{
					AddNumberPattern(patterns, sb.ToString(), i - sb.Length);
					sb.Remove(0, sb.Length);
				}
			}
			AddNumberPattern(patterns, sb.ToString(), passwordLength - sb.Length);
		}

		private static void AddNumberPattern(List<QePatternInstance>[] patterns,
			string numberString, int i)
		{
		    if (numberString.Length <= 2)
		    {
		        return;
		    }

			var zeroCount = numberString.TakeWhile(t => t == '0').Count();

		    var cost = Log2(zeroCount + 1);
			if(zeroCount < numberString.Length)
			{
				var strNonZero = numberString.Substring(zeroCount);

                double d;
			    if (double.TryParse(strNonZero, out d))
			    {
			        cost += Log2(d);
			    }
			    else
			    {
			        Debug.Assert(false);
			        return;
			    }
			}

			patterns[i].Add(new QePatternInstance(i, numberString.Length, PatternId.Number, cost));
		}

		private static void FindDiffSeqs(char[] password, List<QePatternInstance>[] vPatterns)
		{
		    var d = int.MinValue;
            var p = 0;
			var stringToTest = new string(password) + new string(char.MaxValue, 1);

			for(var i = 1; i < stringToTest.Length; ++i)
			{
				var dCur = stringToTest[i] - stringToTest[i - 1];
			    if (dCur != d)
			    {
			        if ((i - p) >= 3) // At least 3 chars involved
			        {
			            var characterType = GetCharType(stringToTest[p]);
			            var dblCost = characterType.CharSize + Log2(i - p - 1);

			            vPatterns[p].Add(new QePatternInstance(p, i - p, PatternId.DiffSeq, dblCost));
			        }

			        d = dCur;
			        p = i - 1;
			    }
			}
		}

		private static double Log2(double dblValue)
		{
			return Math.Log(dblValue, 2.0);
		}
	}
}
