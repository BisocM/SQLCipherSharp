namespace SQLCipherSharp
{
    internal static class Config
    {
        public const int SaltMask = 0x3a;
        public const int KeySize = 32; // 256-bit AES
        public const int KeyIterations = 64000;
        public const int HmacKeySize = 32;
        public const int HmacKeyIterations = 2;
        public const int PageSize = 1024;
        public const int IVSize = 16;
        public const int ReserveSize = 48;
        public const int HmacSize = 20;
    }
}
