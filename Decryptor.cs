using System.Collections.Concurrent;
using System.Text;

namespace SQLCipherSharp
{
    public class Decryptor(Utility utility)
    {

        // SQLCipher 3.x defaults
        private const int SALT_MASK = 0x3a;
        private const int KEY_SIZE = 32; // 256-bit AES-CBC
        private const int KDF_ITERATIONS = 64000;
        private const int HMAC_KEY_SIZE = 32;
        private const int HMAC_KEY_ITER = 2;
        private const int PAGE_SIZE = 1024;
        private const int IV_SIZE = 16;
        private const int RESERVE_SIZE = 48;
        private const int HMAC_SIZE = 20;

        #region Sync Decrypt

        public byte[] DecryptDefault(byte[] raw, byte[] password) =>
            Decrypt(raw, password, SALT_MASK, KEY_SIZE, KDF_ITERATIONS, HMAC_KEY_SIZE, HMAC_KEY_ITER, PAGE_SIZE, IV_SIZE, RESERVE_SIZE, HMAC_SIZE);

        public byte[] Decrypt(byte[] raw, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter, int pageSz, int ivSz, int reserveSz, int hmacSz)
        {
            int saltSz = 16;
            byte[] salt = new byte[saltSz];
            Array.Copy(raw, salt, saltSz);
            (byte[] key, byte[] hmacKey) = utility.KeyDerive(salt, password, saltMask, keySz, keyIter, hmacKeySz, hmacKeyIter);

            byte[] dec = Encoding.UTF8.GetBytes("SQLite format 3\0");
            int numPages = (int)Math.Ceiling((double)raw.Length / pageSz);

            ConcurrentDictionary<int, byte[]> decryptedPages = new();
            ParallelOptions parallelOptions = new() { MaxDegreeOfParallelism = Environment.ProcessorCount * 2 };

            Parallel.For(0, numPages, parallelOptions, i =>
            {
                byte[] page = utility.GetPage(raw, pageSz, i + 1);
                if (i == 0)
                {
                    byte[] temp = new byte[page.Length - saltSz];
                    Array.Copy(page, saltSz, temp, 0, page.Length - saltSz);
                    page = temp;
                }

                byte[] pageContent = new byte[page.Length - reserveSz];
                Array.Copy(page, 0, pageContent, 0, pageContent.Length);

                byte[] reserve = new byte[reserveSz];
                Array.Copy(page, page.Length - reserveSz, reserve, 0, reserveSz);

                byte[] iv = new byte[ivSz];
                Array.Copy(reserve, 0, iv, 0, ivSz);

                byte[] hmacOld = new byte[hmacSz];
                Array.Copy(reserve, ivSz, hmacOld, 0, hmacSz);

                byte[] dataForHmac = utility.ConcatArrays(pageContent, reserve.Take(ivSz).ToArray());
                byte[] hmacNew = utility.GenerateHMAC(hmacKey, dataForHmac, i + 1);

                if (!utility.CompareByteArrays(hmacOld, hmacNew))
                    throw new Exception($"HMAC check failed in page {i + 1}.");

                byte[] pageDec = utility.DecryptAES(pageContent, key, iv);
                byte[] randomBytes = utility.RandomBytes(reserveSz);
                byte[] concatenated = utility.ConcatArrays(pageDec, randomBytes);

                decryptedPages.TryAdd(i, concatenated);
            });

            using MemoryStream ms = new(dec.Length + numPages * (pageSz + reserveSz));
            ms.Write(dec, 0, dec.Length);

            for (int i = 0; i < numPages; i++)
                if (decryptedPages.TryGetValue(i, out byte[]? pageData) && pageData != null)
                    ms.Write(pageData, 0, pageData.Length);

            return ms.ToArray();
        }

        #endregion

        #region Async Decrypt

        public Task<byte[]> DecryptDefaultAsync(byte[] raw, byte[] password) =>
            DecryptAsync(raw, password, SALT_MASK, KEY_SIZE, KDF_ITERATIONS, HMAC_KEY_SIZE, HMAC_KEY_ITER, PAGE_SIZE, IV_SIZE, RESERVE_SIZE, HMAC_SIZE);

        public async Task<byte[]> DecryptAsync(byte[] raw, byte[] password, int saltMask, int keySz, int keyIter, int hmacKeySz, int hmacKeyIter, int pageSz, int ivSz, int reserveSz, int hmacSz)
        {
            int saltSz = 16;
            byte[] salt = new byte[saltSz];
            Array.Copy(raw, salt, saltSz);
            (byte[] key, byte[] hmacKey) = utility.KeyDerive(salt, password, saltMask, keySz, keyIter, hmacKeySz, hmacKeyIter);

            byte[] dec = Encoding.UTF8.GetBytes("SQLite format 3\0");
            int numPages = (int)Math.Ceiling((double)raw.Length / pageSz);

            ConcurrentBag<(int, byte[])> decryptedPages = new();
            ParallelOptions parallelOptions = new() { MaxDegreeOfParallelism = Environment.ProcessorCount * 2 };

            await Parallel.ForEachAsync(Enumerable.Range(0, numPages), parallelOptions, async (i, cancellationToken) =>
            {
                int dataOffset = i * pageSz;
                byte[] pageData = new byte[pageSz + reserveSz];
                Array.Copy(raw, dataOffset, pageData, 0, pageData.Length);

                if (i == 0)
                {
                    byte[] temp = new byte[pageData.Length - saltSz];
                    Array.Copy(pageData, saltSz, temp, 0, temp.Length);
                    pageData = temp;
                }

                byte[] pageContent = new byte[pageSz];
                Array.Copy(pageData, 0, pageContent, 0, pageContent.Length);

                byte[] reserve = new byte[reserveSz];
                Array.Copy(pageData, pageSz, reserve, 0, reserve.Length);

                byte[] iv = new byte[ivSz];
                Array.Copy(reserve, 0, iv, 0, ivSz);

                byte[] hmacOld = new byte[hmacSz];
                Array.Copy(reserve, ivSz, hmacOld, 0, hmacSz);

                byte[] dataForHmac = utility.ConcatArrays(pageContent, iv);
                byte[] hmacNew = await utility.GenerateHMACAsync(hmacKey, dataForHmac, i + 1);

                if (!utility.CompareByteArrays(hmacOld, hmacNew))
                    throw new Exception($"HMAC check failed in page {i + 1}.");

                byte[] pageDec = await utility.DecryptAESAsync(pageContent, key, iv);
                decryptedPages.Add((i, pageDec));
            });

            using MemoryStream ms = new(dec.Length + (numPages * pageSz));
            await ms.WriteAsync(dec);

            foreach (var (index, pageData) in decryptedPages.OrderBy(p => p.Item1))
            {
                await ms.WriteAsync(pageData);
            }

            return ms.ToArray();
        }

        #endregion
    }
}