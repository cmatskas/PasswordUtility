using System.IO;

namespace PasswordUtility.Cipher
{
	/// <summary>
	/// Interface of an encryption/decryption class.
	/// </summary>
	public interface ICipherEngine
	{
		/// <summary>
		/// UUID of the engine. If you want to write an engine/plugin,
		/// please contact the KeePass team to obtain a new UUID.
		/// </summary>
		PwUuid CipherUuid
		{
			get;
		}

		/// <summary>
		/// String displayed in the list of available encryption/decryption
		/// engines in the GUI.
		/// </summary>
		string DisplayName
		{
			get;
		}

		/// <summary>
		/// Encrypt a stream.
		/// </summary>
		/// <param name="sPlainText">Stream to read the plain-text from.</param>
		/// <param name="pbKey">Key to use.</param>
		/// <param name="pbIV">Initialization vector.</param>
		/// <returns>Stream, from which the encrypted data can be read.</returns>
		Stream EncryptStream(Stream sPlainText, byte[] pbKey, byte[] pbIV);

		/// <summary>
		/// Decrypt a stream.
		/// </summary>
		/// <param name="sEncrypted">Stream to read the encrypted data from.</param>
		/// <param name="pbKey">Key to use.</param>
		/// <param name="pbIV">Initialization vector.</param>
		/// <returns>Stream, from which the decrypted data can be read.</returns>
		Stream DecryptStream(Stream sEncrypted, byte[] pbKey, byte[] pbIV);
	}
}
