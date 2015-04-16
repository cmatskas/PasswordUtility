using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using KeePassLib.Utility;

namespace PasswordUtility
{
	/// <summary>
	/// Contains various static time structure manipulation and conversion
	/// routines.
	/// </summary>
	public static class TimeUtil
	{
		public const int PwTimeLength = 7;
		private static string dateTimefStd;
		private static string dateTimefDate;

		/// <summary>
		/// Pack a <c>DateTime</c> object into 5 bytes. Layout: 2 zero bits,
		/// year 12 bits, month 4 bits, day 5 bits, hour 5 bits, minute 6
		/// bits, second 6 bits.
		/// </summary>
		/// <param name="dateTime"></param>
		/// <returns></returns>
		public static byte[] PackTime(DateTime dateTime)
		{
			var pb = new byte[5];

			pb[0] = (byte)((dateTime.Year >> 6) & 0x3F);
			pb[1] = (byte)(((dateTime.Year & 0x3F) << 2) | ((dateTime.Month >> 2) & 0x03));
			pb[2] = (byte)(((dateTime.Month & 0x03) << 6) | ((dateTime.Day & 0x1F) << 1) |
				((dateTime.Hour >> 4) & 0x01));
			pb[3] = (byte)(((dateTime.Hour & 0x0F) << 4) | ((dateTime.Minute >> 2) & 0x0F));
			pb[4] = (byte)(((dateTime.Minute & 0x03) << 6) | (dateTime.Second & 0x3F));

			return pb;
		}

		/// <summary>
		/// Unpack a packed time (5 bytes, packed by the <c>PackTime</c>
		/// member function) to a <c>DateTime</c> object.
		/// </summary>
		/// <param name="pb">Packed time, 5 bytes.</param>
		/// <returns>Unpacked <c>DateTime</c> object.</returns>
		public static DateTime UnpackTime(byte[] pb)
		{
			Debug.Assert((pb != null) && (pb.Length == 5));
		    if (pb == null)
		    {
		        throw new ArgumentNullException("pb");
		    }

		    if (pb.Length != 5)
		    {
		        throw new ArgumentException();
		    }

			int n1 = pb[0], n2 = pb[1], n3 = pb[2], n4 = pb[3], n5 = pb[4];

			// Unpack 5 byte structure to date and time
			var year = (n1 << 6) | (n2 >> 2);
			var month = ((n2 & 0x00000003) << 2) | (n3 >> 6);
			var day = (n3 >> 1) & 0x0000001F;
			var hour = ((n3 & 0x00000001) << 4) | (n4 >> 4);
			var minute = ((n4 & 0x0000000F) << 2) | (n5 >> 6);
			var second = n5 & 0x0000003F;

			return new DateTime(year, month, day, hour, minute, second);
		}

		/// <summary>
		/// Pack a <c>DateTime</c> object into 7 bytes (<c>PW_TIME</c>).
		/// </summary>
		/// <param name="dateTime">Object to be encoded.</param>
		/// <returns>Packed time, 7 bytes (<c>PW_TIME</c>).</returns>
		public static byte[] PackPwTime(DateTime dateTime)
		{
			Debug.Assert(PwTimeLength == 7);

			var pb = new byte[7];
			pb[0] = (byte)(dateTime.Year & 0xFF);
			pb[1] = (byte)(dateTime.Year >> 8);
			pb[2] = (byte)dateTime.Month;
			pb[3] = (byte)dateTime.Day;
			pb[4] = (byte)dateTime.Hour;
			pb[5] = (byte)dateTime.Minute;
			pb[6] = (byte)dateTime.Second;

			return pb;
		}

		/// <summary>
		/// Unpack a packed time (7 bytes, <c>PW_TIME</c>) to a <c>DateTime</c> object.
		/// </summary>
		/// <param name="pb">Packed time, 7 bytes.</param>
		/// <returns>Unpacked <c>DateTime</c> object.</returns>
		public static DateTime UnpackPwTime(byte[] pb)
		{
			Debug.Assert(PwTimeLength == 7);

			Debug.Assert(pb != null);
		    if (pb == null)
		    {
		        throw new ArgumentNullException("pb");
		    }

			Debug.Assert(pb.Length == 7);
		    if (pb.Length != 7)
		    {
		        throw new ArgumentException();
		    }

			return new DateTime((pb[1] << 8) | pb[0], pb[2], pb[3], pb[4], pb[5], pb[6]);
		}

		/// <summary>
		/// Convert a <c>DateTime</c> object to a displayable string.
		/// </summary>
		/// <param name="dateTime"><c>DateTime</c> object to convert to a string.</param>
		/// <returns>String representing the specified <c>DateTime</c> object.</returns>
		public static string ToDisplayString(DateTime dateTime)
		{
			return dateTime.ToString(CultureInfo.CurrentCulture);
		}

		public static string ToDisplayStringDateOnly(DateTime dateTime)
		{
			return dateTime.ToString("d");
		}

		public static DateTime FromDisplayString(string display)
		{
			DateTime dateTime;
		    if (DateTime.TryParse(display, out dateTime))
		    {
		        return dateTime;
		    }

			if((dateTimefStd == null) || (dateTimefDate == null))
			{
				DateTime dateTimeUni = new DateTime(2111, 3, 4, 5, 6, 7);
				dateTimefStd = DeriveCustomFormat(ToDisplayString(dateTimeUni), dateTimeUni);
				dateTimefDate = DeriveCustomFormat(ToDisplayStringDateOnly(dateTimeUni), dateTimeUni);
			}
			
            const DateTimeStyles dateTimes = DateTimeStyles.AllowWhiteSpaces;
		    if (DateTime.TryParseExact(display, dateTimefStd, null, dateTimes, out dateTime))
		    {
		        return dateTime;
		    }

		    if (DateTime.TryParseExact(display, dateTimefDate, null, dateTimes, out dateTime))
		    {
		        return dateTime;
		    }

			Debug.Assert(false);
			return DateTime.Now;
		}

		private static string DeriveCustomFormat(string strdateTime, DateTime dateTime)
		{
			string[] vPlh = new string[] {
				// Names, sorted by length
				"MMMM", "dddd",
				"MMM", "ddd",
				"gg", "g",

				// Numbers, the ones with prefix '0' first
				"yyyy", "yyy", "yy", "y",
				"MM", "M",
				"dd", "d",
				"HH", "hh", "H", "h",
				"mm", "m",
				"ss", "s",

				"tt", "t"
			};

			List<string> lValues = new List<string>();
			foreach(string strPlh in vPlh)
			{
				string strEval = strPlh;
				if(strEval.Length == 1) strEval = @"%" + strPlh; // Make custom

				lValues.Add(dateTime.ToString(strEval));
			}

			StringBuilder sbAll = new StringBuilder();
			sbAll.Append("dfFghHKmMstyz:/\"\'\\%");
			sbAll.Append(strdateTime);
			foreach(string strVEnum in lValues) { sbAll.Append(strVEnum); }

			List<char> lCodes = new List<char>();
			for(int i = 0; i < vPlh.Length; ++i)
			{
				char ch = StrUtil.GetUnusedChar(sbAll.ToString());
				lCodes.Add(ch);
				sbAll.Append(ch);
			}

			string str = strdateTime;
			for(int i = 0; i < vPlh.Length; ++i)
			{
				string strValue = lValues[i];
				if(string.IsNullOrEmpty(strValue)) continue;

				str = str.Replace(strValue, new string(lCodes[i], 1));
			}

			StringBuilder sbFmt = new StringBuilder();
			bool bInLiteral = false;
			foreach(char ch in str)
			{
				int iCode = lCodes.IndexOf(ch);

				// The escape character doesn't work correctly (e.g.
				// "dd\\.MM\\.yyyy\\ HH\\:mm\\:ss" doesn't work, but
				// "dd'.'MM'.'yyyy' 'HH':'mm':'ss" does); use '' instead

				// if(iCode >= 0) sbFmt.Append(vPlh[iCode]);
				// else // Literal
				// {
				//	sbFmt.Append('\\');
				//	sbFmt.Append(ch);
				// }

				if(iCode >= 0)
				{
					if(bInLiteral) { sbFmt.Append('\''); bInLiteral = false; }
					sbFmt.Append(vPlh[iCode]);
				}
				else // Literal
				{
					if(!bInLiteral) { sbFmt.Append('\''); bInLiteral = true; }
					sbFmt.Append(ch);
				}
			}
			if(bInLiteral) sbFmt.Append('\'');

			return sbFmt.ToString();
		}

		public static string SerializeUtc(DateTime dateTime)
		{
			string str = dateTime.ToUniversalTime().ToString("s");
			if(str.EndsWith("Z") == false) str += "Z";
			return str;
		}

		public static bool TryDeserializeUtc(string str, out DateTime dateTime)
		{
		    if (str == null)
		    {
		        throw new ArgumentNullException("str");
		    }

		    if (str.EndsWith("Z"))
		    {
		        str = str.Substring(0, str.Length - 1);
		    }

			var result = StrUtil.TryParseDateTime(str, out dateTime);
		    if (result)
		    {
		        dateTime = dateTime.ToLocalTime();
		    }

			return result;
		}

		private static DateTime? dateTimeUnixRoot;
		public static DateTime ConvertUnixTime(double dateTimeUnix)
		{
		    try
		    {
		        if (!dateTimeUnixRoot.HasValue)
		        {
		            dateTimeUnixRoot = (new DateTime(1970, 1, 1, 0, 0, 0, 0,
		                DateTimeKind.Utc)).ToLocalTime();
		        }

		        return dateTimeUnixRoot.Value.AddSeconds(dateTimeUnix);
		    }
		    catch (Exception)
		    {
		        Debug.Assert(false);
		    }

			return DateTime.Now;
		}

		private static string[] months;
		/// <summary>
		/// Parse a US textual date string, like e.g. "January 02, 2012".
		/// </summary>
		public static DateTime? ParseUsTextDate(string date)
		{
		    if (date == null)
		    {
		        Debug.Assert(false); 
                // return null;
		    }

			if(months == null)
			{
			    months = new[]
			    {
			        "January", "February", "March",
			        "April", "May", "June", "July", "August", "September",
			        "October", "November", "December"
			    };
			}

			var dateString = date.Trim();
		    for (var i = 0; i < months.Length; ++i)
		    {
		        if (!dateString.StartsWith(months[i], StrUtil.CaseIgnoreCmp))
		        {
		            continue;
		        }

		        dateString = dateString.Substring(months[i].Length);
		        var splitDate = dateString.Split(',', ';');

		        if (splitDate.Length != 2)
		        {
		            return null;
		        }

		        var dayString = splitDate[0].Trim().TrimStart('0');
		        int iDay, iYear;
		        if (int.TryParse(dayString, out iDay) && int.TryParse(splitDate[1].Trim(), out iYear))
		        {
		            return new DateTime(iYear, i + 1, iDay);
		        }

		        return null;
		    }

		    return null;
		}

		private static readonly DateTime DateTimeInvMin = new DateTime(2999, 12, 27, 23, 59, 59);
		private static readonly DateTime DateTimeInvMax = new DateTime(2999, 12, 29, 23, 59, 59);
		public static int Compare(DateTime dateTimeA, DateTime dateTimeB, bool unkIsPast)
		{
		    if (!unkIsPast)
		    {
		        return dateTimeA.CompareTo(dateTimeB);
		    }

		    var bInvA = ((dateTimeA >= DateTimeInvMin) && (dateTimeA <= DateTimeInvMax) &&
		                 (dateTimeA.Minute == 59) && (dateTimeA.Second == 59));
		    var bInvB = ((dateTimeB >= DateTimeInvMin) && (dateTimeB <= DateTimeInvMax) &&
		                 (dateTimeB.Minute == 59) && (dateTimeB.Second == 59));

		    if (bInvA)
		    {
		        return (bInvB ? 0 : -1);
		    }

		    return bInvB ? 1 : dateTimeA.CompareTo(dateTimeB);
		}
	}
}
