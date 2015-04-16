using PasswordUtility.Security;

namespace PasswordUtility.PasswordGenerator
{
	public abstract class CustomPwGenerator
	{
		/// <summary>
		/// Each custom password generation algorithm must have
		/// its own unique UUID.
		/// </summary>
		public abstract PwUuid Uuid { get; }

		/// <summary>
		/// Displayable name of the password generation algorithm.
		/// </summary>
		public abstract string Name { get; }

		public virtual bool SupportsOptions
		{
			get { return false; }
		}

		/// <summary>
		/// Password generation function.
		/// </summary>
		/// <param name="prf">Password generation options chosen
		/// by the user. This may be <c>null</c>, if the default
		/// options should be used.</param>
		/// <param name="crsRandomSource">Source that the algorithm
		/// can use to generate random numbers.</param>
		/// <returns>Generated password or <c>null</c> in case
		/// of failure. If returning <c>null</c>, the caller assumes
		/// that an error message has already been shown to the user.</returns>
		public abstract ProtectedString Generate(PwProfile prf,
			CryptoRandomStream crsRandomSource);

		public virtual string GetOptions(string strCurrentOptions)
		{
			return string.Empty;
		}
	}
}
