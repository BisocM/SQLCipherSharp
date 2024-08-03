using System.Security.Cryptography;
using System.Text;

namespace SQLCipherSharp
{
    public class Utility
    {
        public byte[] DecryptAES(byte[] raw, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = 256;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream msDecrypt = new(raw);
            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            using MemoryStream ms = new();

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                ms.Write(buffer, 0, bytesRead);

            return ms.ToArray();
        }

        public async Task<byte[]> DecryptAESAsync(byte[] raw, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = 256;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream msDecrypt = new(raw);
            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            using MemoryStream ms = new();

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = await csDecrypt.ReadAsync(buffer, 0, buffer.Length)) > 0)
                await ms.WriteAsync(buffer, 0, bytesRead);

            return ms.ToArray();
        }

        public byte[] EncryptAES(byte[] raw, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = 256;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            using MemoryStream msEncrypt = new();
            using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);

            csEncrypt.Write(raw, 0, raw.Length);
            csEncrypt.FlushFinalBlock();

            return msEncrypt.ToArray();
        }

        public byte[] ConcatArrays(params byte[][] arrays)
        {
            byte[] result = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
            return result;
        }

        public bool IsValidDatabaseHeader(byte[] header) =>
            header.Take(16).SequenceEqual(Encoding.UTF8.GetBytes("SQLite format 3\0")) &&
            IsValidDecryptedHeader(header.Skip(16).ToArray());

        public bool IsValidDecryptedHeader(byte[] header) =>
            header[21 - 16] == 64 && header[22 - 16] == 32 && header[23 - 16] == 32;

        public int GetPageSizeFromDatabaseHeader(byte[] header)
        {
            int pageSz = 256 * header[16] + header[17];
            return pageSz == 1 ? 65536 : pageSz;
        }

        public int GetReservedSizeFromDatabaseHeader(byte[] header) => header[20];

        public bool IsValidPageSize(int pageSz) => pageSz >= 512 && pageSz == (int)Math.Pow(2, (int)Math.Log(pageSz, 2));

        public byte[] GetPage(byte[] raw, int pageSz, int pageNo) => raw.Skip(pageSz * (pageNo - 1)).Take(pageSz).ToArray();

        public (byte[], byte[]) KeyDerive(byte[] salt, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter)
        {
            // Derive the encryption key
            using Rfc2898DeriveBytes pbkdf2 = new(password, salt, keyIter, HashAlgorithmName.SHA1);
            byte[] key = pbkdf2.GetBytes(keySz);

            // XOR the salt with saltMask to create HMAC salt
            byte[] hmacSalt = new byte[salt.Length];
            for (int i = 0; i < salt.Length; i++)
                hmacSalt[i] = (byte)(salt[i] ^ saltMask);

            // Derive the HMAC key
            using Rfc2898DeriveBytes pbkdf2Hmac = new(key, hmacSalt, hmacKeyIter, HashAlgorithmName.SHA1);
            byte[] hmacKey = pbkdf2Hmac.GetBytes(hmacKeySz);

            return (key, hmacKey);
        }

        public byte[] GenerateHMAC(byte[] hmacKey, byte[] content, int pageNo)
        {
            using HMACSHA1 hmac = new(hmacKey);
            byte[] pageNoBytes = BitConverter.GetBytes((uint)pageNo);

            // Ensure little-endian byte order for page number
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(pageNoBytes);

            byte[] combinedContent = new byte[content.Length + pageNoBytes.Length];
            Buffer.BlockCopy(content, 0, combinedContent, 0, content.Length);
            Buffer.BlockCopy(pageNoBytes, 0, combinedContent, content.Length, pageNoBytes.Length);

            return hmac.ComputeHash(combinedContent);
        }

        public async Task<byte[]> GenerateHMACAsync(byte[] hmacKey, byte[] content, int pageNo)
        {
            using HMACSHA1 hmac = new(hmacKey);
            byte[] pageNoBytes = BitConverter.GetBytes((uint)pageNo);

            // Ensure little-endian byte order for page number
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(pageNoBytes);

            byte[] combinedContent = new byte[content.Length + pageNoBytes.Length];
            Buffer.BlockCopy(content, 0, combinedContent, 0, content.Length);
            Buffer.BlockCopy(pageNoBytes, 0, combinedContent, content.Length, pageNoBytes.Length);

            return await Task.Run(() => hmac.ComputeHash(combinedContent));
        }

        public byte[] RandomBytes(int n)
        {
            byte[] randomBytes = new byte[n];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return randomBytes;
        }

        public bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}