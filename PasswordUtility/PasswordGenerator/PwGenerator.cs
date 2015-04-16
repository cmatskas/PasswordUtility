using System;
using System.Diagnostics;
using PasswordUtility.Security;

namespace PasswordUtility.PasswordGenerator
{
	public enum PwgError
	{
		Success = 0,
		Unknown = 1,
		TooFewCharacters = 2,
		UnknownAlgorithm = 3
	}

	/// <summary>
	/// Utility functions for generating random passwords.
	/// </summary>
	public static class PwGenerator
	{
		public static PwgError Generate(out ProtectedString psOut,
			PwProfile pwProfile, byte[] pbUserEntropy,
			CustomPwGeneratorPool pwAlgorithmPool)
		{
			Debug.Assert(pwProfile != null);
			if(pwProfile == null) throw new ArgumentNullException("pwProfile");

			var crs = CreateCryptoStream(pbUserEntropy);
			var e = PwgError.Unknown;

		    if (pwProfile.GeneratorType == PasswordGeneratorType.CharSet)
		    {
		        e = CharSetBasedGenerator.Generate(out psOut, pwProfile, crs);
		    }
			else if (pwProfile.GeneratorType == PasswordGeneratorType.Pattern)
			{
			    e = PatternBasedGenerator.Generate(out psOut, pwProfile, crs);
			}
			else if (pwProfile.GeneratorType == PasswordGeneratorType.Custom)
			{
			    e = GenerateCustom(out psOut, pwProfile, crs, pwAlgorithmPool);
			}
			else
			{
			    psOut = ProtectedString.Empty;
			}

			return e;
		}

		private static CryptoRandomStream CreateCryptoStream(byte[] pbAdditionalEntropy)
		{
			byte[] pbKey = CryptoRandom.Instance.GetRandomBytes(256);

			// Mix in additional entropy
			if((pbAdditionalEntropy != null) && (pbAdditionalEntropy.Length > 0))
			{
				for(int nKeyPos = 0; nKeyPos < pbKey.Length; ++nKeyPos)
					pbKey[nKeyPos] ^= pbAdditionalEntropy[nKeyPos % pbAdditionalEntropy.Length];
			}

			return new CryptoRandomStream(CrsAlgorithm.Salsa20, pbKey);
		}

		internal static char GenerateCharacter(PwProfile pwProfile,
			PwCharSet pwCharSet, CryptoRandomStream crsRandomSource)
		{
		    if (pwCharSet.Size == 0)
		    {
		        return char.MinValue;
		    }

			var index = crsRandomSource.GetRandomUInt64();
			index %= pwCharSet.Size;

			var ch = pwCharSet[(uint)index];

		    if (pwProfile.NoRepeatingCharacters)
		    {
		        pwCharSet.Remove(ch);
		    }

			return ch;
		}

		internal static void PrepareCharSet(PwCharSet pwCharSet, PwProfile pwProfile)
		{
			pwCharSet.Remove(PwCharSet.Invalid);

			if(pwProfile.ExcludeLookAlike) pwCharSet.Remove(PwCharSet.LookAlike);

			if(pwProfile.ExcludeCharacters.Length > 0)
				pwCharSet.Remove(pwProfile.ExcludeCharacters);
		}

		internal static void ShufflePassword(char[] password,
			CryptoRandomStream crsRandomSource)
		{
		    if (string.IsNullOrEmpty(password.ToString()))
		    {
		        return;
		    }

		    if (crsRandomSource == null)
		    {
		        return;
		    }

			if(password.Length <= 1) {
                return; // Nothing to shuffle
}

			for(var nSelect = 0; nSelect < password.Length; ++nSelect)
			{
				var randomIndex = crsRandomSource.GetRandomUInt64();
				randomIndex %= (ulong)(password.Length - nSelect);

				char chTemp = password[nSelect];
				password[nSelect] = password[nSelect + (int)randomIndex];
				password[nSelect + (int)randomIndex] = chTemp;
			}
		}

		private static PwgError GenerateCustom(out ProtectedString psOut,
			PwProfile pwProfile, CryptoRandomStream crs,
			CustomPwGeneratorPool pwAlgorithmPool)
		{
			psOut = ProtectedString.Empty;

			Debug.Assert(pwProfile.GeneratorType == PasswordGeneratorType.Custom);
		    if (pwAlgorithmPool == null)
		    {
		        return PwgError.UnknownAlgorithm;
		    }

			var strId = pwProfile.CustomAlgorithmUuid;
		    if (string.IsNullOrEmpty(strId))
		    {
		        return PwgError.UnknownAlgorithm;
		    }

			var pbUuid = Convert.FromBase64String(strId);
			var uuid = new PwUuid(pbUuid);
			var pwg = pwAlgorithmPool.Find(uuid);
		    if (pwg == null)
		    {
		        return PwgError.UnknownAlgorithm;
		    }

			var pwd = pwg.Generate(pwProfile.CloneDeep(), crs);
		    if (pwd == null)
		    {
		        return PwgError.Unknown;
		    }

			psOut = pwd;
			return PwgError.Success;
		}
	}
}
