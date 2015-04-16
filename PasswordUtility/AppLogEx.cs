using System;
using System.IO;

namespace PasswordUtility
{
	/// <summary>
	/// Application-wide logging services.
	/// </summary>
	public static class AppLogEx
	{
		private static StreamWriter streamWriter;

		public static void Open(string strPrefix)
		{
		}

		public static void Close()
		{
		    if (streamWriter == null)
		    {
		        return;
		    }

			streamWriter.Close();
			streamWriter = null;
		}

		public static void Log(string strText)
		{
		    if (streamWriter == null)
		    {
		        return;
		    }

			if(strText == null) streamWriter.WriteLine();
			else streamWriter.WriteLine(strText);
		}

		public static void Log(Exception ex)
		{
			if(streamWriter == null) return;

			if(ex == null) streamWriter.WriteLine();
			else streamWriter.WriteLine(ex.ToString());
		}
	}
}
