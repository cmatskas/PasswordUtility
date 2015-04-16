using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace PasswordUtility.PasswordGenerator
{
	public sealed class CustomPwGeneratorPool : IEnumerable<CustomPwGenerator>
	{
		private readonly List<CustomPwGenerator> passwordGenerators = new List<CustomPwGenerator>();

		public int Count
		{
			get { return passwordGenerators.Count; }
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return passwordGenerators.GetEnumerator();
		}

		public IEnumerator<CustomPwGenerator> GetEnumerator()
		{
			return passwordGenerators.GetEnumerator();
		}

		public void Add(CustomPwGenerator pwg)
		{
			if(pwg == null) throw new ArgumentNullException("pwg");

			PwUuid uuid = pwg.Uuid;
			if(uuid == null) throw new ArgumentException();

			int nIndex = FindIndex(uuid);

			if(nIndex >= 0) passwordGenerators[nIndex] = pwg; // Replace
			else passwordGenerators.Add(pwg);
		}

		public CustomPwGenerator Find(PwUuid uuid)
		{
		    if (uuid == null)
		    {
		        throw new ArgumentNullException("uuid");
		    }

		    return passwordGenerators.FirstOrDefault(pwg => uuid.Equals(pwg.Uuid));
		}

		public CustomPwGenerator Find(string strName)
		{
		    if (strName == null)
		    {
		        throw new ArgumentNullException("strName");
		    }

		    return passwordGenerators.FirstOrDefault(pwg => pwg.Name == strName);
		}

		private int FindIndex(PwUuid uuid)
		{
			if(uuid == null) throw new ArgumentNullException("uuid");

			for(int i = 0; i < passwordGenerators.Count; ++i)
			{
				if(uuid.Equals(passwordGenerators[i].Uuid)) return i;
			}

			return -1;
		}

		public bool Remove(PwUuid uuid)
		{
			if(uuid == null) throw new ArgumentNullException("uuid");

			int nIndex = FindIndex(uuid);
			if(nIndex < 0) return false;

			passwordGenerators.RemoveAt(nIndex);
			return true;
		}
	}
}
