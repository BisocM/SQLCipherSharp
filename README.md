# SQLCipherSharp

**SQLCipherSharp** is a simple and lightweight C# library designed for SQLCipher decryption.

## Features

- **Synchronous and Asynchronous Decryption**: Supports both sync and async methods to decrypt SQLCipher-encrypted databases.
- **Flexible Configuration**: Easily adjustable settings for key size, iterations, page size, and more.
- **Dependency Injection**: Supports integration with DI containers.

## Usage

### Synchronous Decryption

Here's a simple example of how to decrypt a SQLCipher-encrypted database synchronously:

```csharp
using SQLCipherSharp;

// Assuming `utility` is an instance of the Utility class, injected or instantiated.
var decryptor = new Decryptor(utility);
byte[] encryptedData = ...; // Your encrypted data
byte[] password = Encoding.UTF8.GetBytes("your-password");

byte[] decryptedData = decryptor.DecryptDefault(encryptedData, password);
```

### Asynchronous Decryption

For asynchronous decryption:

```csharp
using SQLCipherSharp;
using System.Threading.Tasks;

// Assuming `utility` is an instance of the Utility class, injected or instantiated.
var decryptor = new Decryptor(utility);
byte[] encryptedData = ...; // Your encrypted data
byte[] password = Encoding.UTF8.GetBytes("your-password");

byte[] decryptedData = await decryptor.DecryptDefaultAsync(encryptedData, password);
```

## Configuration

SQLCipherSharp uses sensible defaults based on SQLCipher 3.x, but you can customize various parameters such as:

- **Salt Mask**
- **Key Size**
- **Key Derivation Iterations**
- **HMAC Key Size and Iterations**
- **Page Size**
- **IV Size**
- **Reserve Size**
- **HMAC Size**

These can be passed directly to the `Decrypt` and `DecryptAsync` methods if you need to override the defaults.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you have suggestions or find any bugs.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---