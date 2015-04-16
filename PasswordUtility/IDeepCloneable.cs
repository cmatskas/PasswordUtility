namespace PasswordUtility
{
	/// <summary>
	/// Interface for objects that are deeply cloneable.
	/// </summary>
	/// <typeparam name="T">Reference type.</typeparam>
	public interface IDeepCloneable<T> where T : class
	{
		/// <summary>
		/// Deeply clone the object.
		/// </summary>
		/// <returns>Cloned object.</returns>
		T CloneDeep();
	}
}
