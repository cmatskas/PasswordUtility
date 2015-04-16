using System;
using System.Runtime.InteropServices;
using System.IO;

namespace PasswordUtility.Native
{
	internal static partial class NativeMethods
	{
		internal const int MAX_PATH = 260;

		[DllImport("KeePassLibC32.dll", EntryPoint = "TransformKey256")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool TransformKey32(IntPtr pBuf256,
			IntPtr pKey256, UInt64 uRounds);

		[DllImport("KeePassLibC64.dll", EntryPoint = "TransformKey256")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool TransformKey64(IntPtr pBuf256,
			IntPtr pKey256, UInt64 uRounds);

		internal static bool TransformKey(IntPtr pBuf256, IntPtr pKey256,
			UInt64 uRounds)
		{
			if(Marshal.SizeOf(typeof(IntPtr)) == 8)
				return TransformKey64(pBuf256, pKey256, uRounds);
			else
				return TransformKey32(pBuf256, pKey256, uRounds);
		}

		[DllImport("KeePassLibC32.dll", EntryPoint = "TransformKeyBenchmark256")]
		private static extern UInt64 TransformKeyBenchmark32(UInt32 uTimeMs);

		[DllImport("KeePassLibC64.dll", EntryPoint = "TransformKeyBenchmark256")]
		private static extern UInt64 TransformKeyBenchmark64(UInt32 uTimeMs);

		internal static UInt64 TransformKeyBenchmark(UInt32 uTimeMs)
		{
			if(Marshal.SizeOf(typeof(IntPtr)) == 8)
				return TransformKeyBenchmark64(uTimeMs);
			return TransformKeyBenchmark32(uTimeMs);
		}



		private static bool? m_bSupportsLogicalCmp = null;

		private static void TestNaturalComparisonsSupport()
		{
		}

		internal static bool SupportsStrCmpNaturally
		{
			get
			{
			    if (m_bSupportsLogicalCmp.HasValue == false)
			    {
			        TestNaturalComparisonsSupport();
			    }

				return m_bSupportsLogicalCmp.Value;
			}
		}

		internal static int StrCmpNaturally(string x, string y)
		{
			if(m_bSupportsLogicalCmp.HasValue == false) TestNaturalComparisonsSupport();
			if(m_bSupportsLogicalCmp.Value == false) return 0;

			//return StrCmpLogicalW(x, y);
		    return 1;
		}

		internal static string GetUserRuntimeDir()
		{
            return Path.GetTempPath();
		}
	}
}
