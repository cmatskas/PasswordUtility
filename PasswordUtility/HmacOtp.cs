using System;
using System.Globalization;
using System.Security.Cryptography;

namespace PasswordUtility
{
	/// <summary>
	/// Generate HMAC-based one-time passwords as specified in RFC 4226.
	/// </summary>
	public static class HmacOtp
	{
		private static readonly uint[] vDigitsPower = new uint[]{ 1, 10, 100,
			1000, 10000, 100000, 1000000, 10000000, 100000000 };

		public static string Generate(byte[] pbSecret, ulong uFactor,
			uint uCodeDigits, bool bAddChecksum, int iTruncationOffset)
		{
			byte[] pbText = MemUtil.UInt64ToBytes(uFactor);
			Array.Reverse(pbText); // Big-Endian

			HMACSHA1 hsha1 = new HMACSHA1(pbSecret);
			byte[] pbHash = hsha1.ComputeHash(pbText);

			uint uOffset = (uint)(pbHash[pbHash.Length - 1] & 0xF);
			if((iTruncationOffset >= 0) && (iTruncationOffset < (pbHash.Length - 4)))
				uOffset = (uint)iTruncationOffset;

			uint uBinary = (uint)(((pbHash[uOffset] & 0x7F) << 24) |
				((pbHash[uOffset + 1] & 0xFF) << 16) |
				((pbHash[uOffset + 2] & 0xFF) << 8) |
				(pbHash[uOffset + 3] & 0xFF));

			uint uOtp = (uBinary % vDigitsPower[uCodeDigits]);
			if(bAddChecksum)
				uOtp = ((uOtp * 10) + CalculateChecksum(uOtp, uCodeDigits));

			uint uDigits = (bAddChecksum ? (uCodeDigits + 1) : uCodeDigits);
			return uOtp.ToString(NumberFormatInfo.InvariantInfo).PadLeft(
				(int)uDigits, '0');
		}

		private static readonly uint[] vDoubleDigits = new uint[]{ 0, 2, 4, 6, 8,
			1, 3, 5, 7, 9 };

		private static uint CalculateChecksum(uint uNum, uint uDigits)
		{
			bool bDoubleDigit = true;
			uint uTotal = 0;

			while(0 < uDigits--)
			{
				uint uDigit = (uNum % 10);
				uNum /= 10;

				if(bDoubleDigit) uDigit = vDoubleDigits[uDigit];

				uTotal += uDigit;
				bDoubleDigit = !bDoubleDigit;
			}

			uint uResult = (uTotal % 10);
			if(uResult != 0) uResult = 10 - uResult;

			return uResult;
		}
	}
}
