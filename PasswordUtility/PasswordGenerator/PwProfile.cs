using System;
using System.ComponentModel;
using System.Xml.Serialization;
using PasswordUtility.Security;

namespace PasswordUtility.PasswordGenerator
{
	/// <summary>
	/// Type of the password generator. Different types like generators
	/// based on given patterns, based on character sets, etc. are
	/// available.
	/// </summary>
	public enum PasswordGeneratorType
	{
		/// <summary>
		/// Generator based on character spaces/sets, i.e. groups
		/// of characters like lower-case, upper-case or numeric characters.
		/// </summary>
		CharSet = 0,

		/// <summary>
		/// Password generation based on a pattern. The user has provided
		/// a pattern, which describes how the generated password has to
		/// look like.
		/// </summary>
		Pattern = 1,

		Custom = 2
	}

	public sealed class PwProfile : IDeepCloneable<PwProfile>
	{
		private string stringName = string.Empty;
		
        [DefaultValue("")]
		public string Name
		{
			get { return stringName; }
			set { stringName = value; }
		}

		private PasswordGeneratorType generatorType = PasswordGeneratorType.CharSet;
		public PasswordGeneratorType GeneratorType
		{
			get { return generatorType; }
			set { generatorType = value; }
		}

		private bool userEntropy;

		[DefaultValue(false)]
		public bool CollectUserEntropy
		{
			get { return userEntropy; }
			set { userEntropy = value; }
		}

		private uint length = 20;
		public uint Length
		{
			get { return length; }
			set { length = value; }
		}

		private PwCharSet passwordCharSet = new PwCharSet(PwCharSet.UpperCase + PwCharSet.LowerCase + PwCharSet.Digits);
		[XmlIgnore]
		public PwCharSet CharSet
		{
			get { return passwordCharSet; }
			set
			{
			    if (value == null)
			    {
			        throw new ArgumentNullException("value");
			    }
				passwordCharSet = value;
			}
		}

		private string characterSetRanges = string.Empty;
		[DefaultValue("")]
		public string CharSetRanges
		{
			get { UpdateCharSet(true); return characterSetRanges; }
			set
			{
				if(value == null) throw new ArgumentNullException("value");
				characterSetRanges = value;
				UpdateCharSet(false);
			}
		}

		private string characterSetAdditional = string.Empty;
		[DefaultValue("")]
		public string CharSetAdditional
		{
			get { UpdateCharSet(true); return characterSetAdditional; }
			set
			{
				if(value == null) throw new ArgumentNullException("value");
				characterSetAdditional = value;
				UpdateCharSet(false);
			}
		}

		private string pattern = string.Empty;
		[DefaultValue("")]
		public string Pattern
		{
			get { return pattern; }
			set { pattern = value; }
		}

		private bool patternPermute;
		[DefaultValue(false)]
		public bool PatternPermutePassword
		{
			get { return patternPermute; }
			set { patternPermute = value; }
		}

		private bool noLookAlike;
		[DefaultValue(false)]
		public bool ExcludeLookAlike
		{
			get { return noLookAlike; }
			set { noLookAlike = value; }
		}

		private bool noRepeat;
		[DefaultValue(false)]
		public bool NoRepeatingCharacters
		{
			get { return noRepeat; }
			set { noRepeat = value; }
		}

		private string excludedCharacters = string.Empty;
		[DefaultValue("")]
		public string ExcludeCharacters
		{
			get { return excludedCharacters; }
			set
			{
				if(value == null) throw new ArgumentNullException("value");
				excludedCharacters = value;
			}
		}

		private string customId = string.Empty;
		[DefaultValue("")]
		public string CustomAlgorithmUuid
		{
			get { return customId; }
			set
			{
				if(value == null) throw new ArgumentNullException("value");
				customId = value;
			}
		}

		private string customAlgorithmOptions = string.Empty;
		[DefaultValue("")]
		public string CustomAlgorithmOptions
		{
			get { return customAlgorithmOptions; }
			set
			{
				if(value == null) throw new ArgumentNullException("value");
				customAlgorithmOptions = value;
			}
		}

		public PwProfile CloneDeep()
		{
		    var profile = new PwProfile
		    {
		        stringName = stringName,
		        generatorType = generatorType,
		        userEntropy = userEntropy,
		        length = length,
		        passwordCharSet = new PwCharSet(passwordCharSet.ToString()),
		        characterSetRanges = characterSetRanges,
		        characterSetAdditional = characterSetAdditional,
		        pattern = pattern,
		        patternPermute = patternPermute,
		        noLookAlike = noLookAlike,
		        noRepeat = noRepeat,
		        excludedCharacters = excludedCharacters,
		        customId = customId,
		        customAlgorithmOptions = customAlgorithmOptions
		    };


		    return profile;
		}

		private void UpdateCharSet(bool bSetXml)
		{
			if(bSetXml)
			{
				PwCharSet pcs = new PwCharSet(passwordCharSet.ToString());
				characterSetRanges = pcs.PackAndRemoveCharRanges();
				characterSetAdditional = pcs.ToString();
			}
			else
			{
				PwCharSet pcs = new PwCharSet(characterSetAdditional);
				pcs.UnpackCharRanges(characterSetRanges);
				passwordCharSet = pcs;
			}
		}

		public static PwProfile DeriveFromPassword(ProtectedString psPassword)
		{
			var passwordProfile = new PwProfile();
		    if (psPassword == null)
		    {
		        return passwordProfile;
		    }

			var pbUtf8 = psPassword.ReadUtf8();
			var chars = StrUtil.Utf8.GetChars(pbUtf8);

			passwordProfile.GeneratorType = PasswordGeneratorType.CharSet;
			passwordProfile.Length = (uint)chars.Length;

			var passwordSet = passwordProfile.CharSet;
			passwordSet.Clear();

			foreach(char ch in chars)
			{
			    if ((ch >= 'A') && (ch <= 'Z'))
			    {
			        passwordSet.Add(PwCharSet.UpperCase);
			    }
				else if ((ch >= 'a') && (ch <= 'z'))
				{
				    passwordSet.Add(PwCharSet.LowerCase);
				}
				else if ((ch >= '0') && (ch <= '9'))
				{
				    passwordSet.Add(PwCharSet.Digits);
				}
				else if (PwCharSet.SpecialChars.IndexOf(ch) >= 0)
				{
				    passwordSet.Add(PwCharSet.SpecialChars);
				}
				else if (ch == ' ')
				{
				    passwordSet.Add(' ');
				}
				else if (ch == '-')
				{
				    passwordSet.Add('-');
				}
				else if (ch == '_')
				{
				    passwordSet.Add('_');
				}
				else if (PwCharSet.Brackets.IndexOf(ch) >= 0)
				{
				    passwordSet.Add(PwCharSet.Brackets);
				}
				else if (PwCharSet.HighAnsiChars.IndexOf(ch) >= 0)
				{
				    passwordSet.Add(PwCharSet.HighAnsiChars);
				}
				else passwordSet.Add(ch);
			}

			Array.Clear(chars, 0, chars.Length);
			MemUtil.ZeroByteArray(pbUtf8);
			return passwordProfile;
		}

		public bool HasSecurityReducingOption()
		{
			return (noLookAlike || noRepeat || (excludedCharacters.Length > 0));
		}
	}
}
