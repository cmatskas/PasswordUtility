# PasswordUtility
The Passowrd Utility is the library behind the [http://passwordutility.net](http://passwordutility.net) public api service that allows anyone to either validate or generate new random passwords. The library is fairly simple in that it only 
has 2 important classes that you should care about:

- `PwGenerator`
- `QualityEstimation`

## Password Generation
The first one, as the name implies, allows you to generate a new random password. By default, the `PwGenerator.Generate()` method
creates passwords of a given length, as defined by the user, containing only lower case alphabetic characters. The method offers
additional parameters to allow users to generate more complicated passwords that contain numbers, upper case characters and special
characaters. The signature of the method is:

    public static ProtectedString Generate(
      int passwordLength, 
      bool useUpperCase = false, 
      bool useDigits = false, 
      bool useSpecialCharacters = false)
      
By setting the appropriate parameters, you generate the password you need. For example, if you want a password 15 characters
long with upper case and special characters then you would call the method like this:

    var password  = PwGenerator.Generate(15, true, false, true).ReadString();

Notice how we use `.ReadString();` in order to transform the `ProtectedString` to a standard string. You chose what ever meets
your needs best. 

## Password Strength Validation
Another handy feature of this library is the ability to validate a password and check for strength and entropy. The algorithm
behind the calculation is pretty complicated and I chose to re-use the excellent implementation from KeePass rather than to 
roll my own. To validate a password all you have to do is call the QualityEstimation class like the example below:

    uint result = QualityEstimation.EstimatePasswordBits(<YourPasswordString>.ToCharArray());
    
The result of this operation is an unsigned integer between 0 and 100. The closer to 100 the stronger the password is. The method signature
is:
    public static uint EstimatePasswordBits(char[] vPasswordChars);

I hope you find this little library handy and please raise an issue with any requests or bugs.
`
