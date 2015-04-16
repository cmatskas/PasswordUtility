using System;
using PasswordUtility.Security;

namespace PasswordUtility.PasswordGenerator
{
	internal static class CharSetBasedGenerator
	{
		internal static PwgError Generate(out ProtectedString psOut,
			PwProfile pwProfile, CryptoRandomStream crsRandomSource)
		{
			psOut = ProtectedString.Empty;
			if(pwProfile.Length == 0) return PwgError.Success;

			PwCharSet pcs = new PwCharSet(pwProfile.CharSet.ToString());
			char[] vGenerated = new char[pwProfile.Length];

			PwGenerator.PrepareCharSet(pcs, pwProfile);

			for(int nIndex = 0; nIndex < (int)pwProfile.Length; ++nIndex)
			{
				char ch = PwGenerator.GenerateCharacter(pwProfile, pcs,
					crsRandomSource);

				if(ch == char.MinValue)
				{
					Array.Clear(vGenerated, 0, vGenerated.Length);
					return PwgError.TooFewCharacters;
				}

				vGenerated[nIndex] = ch;
			}

			byte[] pbUtf8 = StrUtil.Utf8.GetBytes(vGenerated);
			psOut = new ProtectedString(true, pbUtf8);
			MemUtil.ZeroByteArray(pbUtf8);
			Array.Clear(vGenerated, 0, vGenerated.Length);

			return PwgError.Success;
		}
	}
}
