using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace LiBCAT
{
    internal static class Crypto
    {
        private static class Aes
        {
            private static byte[] EncBlk(byte[] blk, byte[] key) =>
                new AesCryptoServiceProvider()
                {
                    Key = key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                }
                .CreateEncryptor()
                .TransformFinalBlock(blk, 0, 16);

            public static byte[] CTR(byte[] Data, byte[] Key, byte[] IV)
            {
                var Len = Data.Length;
                byte[] OutBuf = new byte[Len], KeyBuf = new byte[16];

                for (int i = 0; i < Len; i += 16)
                {
                    KeyBuf = EncBlk(IV, Key);

                    var ptr = Len - i;

                    if (ptr > 16) ptr = 16;

                    for (int j = 0; j < ptr; j++)
                        OutBuf[i + j] = (byte)(KeyBuf[j] ^ Data[i + j]);

                    for (var j = 15; j >= 0; j--)
                        if (++IV[j] != 0) break;
                }

                return OutBuf;
            }
        }

        internal static readonly string[] Salts =
        {
            "a3e20c5c1cd7b720",
            "7f4c637432c8d420",
            "188d087d92a0c087",
            "8e7d23fa7fafe60f",
            "5252ae57c026d3cb",
            "2650f5e53554f01d",
            "b213a1e986307c9f",
            "875d8b01e3df5d7c",
            "c1b9a5ce866e00b1",
            "6a48ae69161e0138",
            "3f7b0401928b1f46",
            "0e9db55903a10f0e",
            "a8914bcbe7b888f9",
            "b15ef3ed6ce0e4cc",
            "f3b9d9f43dedf569",
            "bda4f7a0508c7462",
            "f5dc3586b1b2a8af",
            "7f6828b6f33dd118",
            "860de88547dcbf70",
            "ccbacacb70d11fb5",
            "b1475e5ea18151b9",
            "5f857ca15cf3374c",
            "cfa747c1d09d4f05",
            "30e7d70cb6f98101",
            "c8b3c78772bdcf43",
            "533dfc0702ed9874",
            "a29301cac5219e5c",
            "5776f5bec1b0df06",
            "1d4ab85a07ac4251",
            "7c1bd512b1cf5092",
            "2691cb8b3f76b411",
            "4400abee651c9eb9"
        };

        public static byte[] GetBcatData(string Url)
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            using (var Cli = new WebClient()) return Cli.DownloadData(Url);
        }

        public static byte[] DecryptBcatData(byte[] Data, ulong TitleID, string Passphrase, bool isRetail)
        {
            using (MemoryStream Strm = new MemoryStream(Data))
            using (BinaryReader Rd = new BinaryReader(Strm))
            {
                Strm.Position += 5;
                var KeySize = (Rd.ReadByte() + 1) << 3;
                Strm.Position++;
                var Index = Rd.ReadByte();
                Strm.Position += 8;
                var IV = Rd.ReadBytes(0x10);
                Strm.Position += 0x100;
                var EncData = Rd.ReadBytes((int)(Strm.Length - 0x120));

                return Aes.CTR(EncData, PBKDF2(KeySize, Passphrase.TBA(), $"{TitleID:x16}{Salts[Index]}".TBA(), 4096), IV);
            }
        }

        private static byte[] PBKDF2(int Len, byte[] Passphrase, byte[] Salt, int IterCount)
        {
            using (var HMAC = new HMACSHA256(Passphrase))
            {
                byte[] ExtKey = new byte[Salt.Length + 4];
                Buffer.BlockCopy(Salt, 0, ExtKey, 0, Salt.Length);

                using (var Strm = new MemoryStream())
                {
                    for (int i = 0; i < Len >> 5; i++)
                    {
                        for (int j = 0; j < 4; j++)
                            ExtKey[Salt.Length + j] = (byte)((i + 1) >> ((3 ^ j) << 3) & 0xff);

                        byte[] MACBuf = HMAC.ComputeHash(ExtKey), Buf = MACBuf;

                        for (int j = 1; j < IterCount; j++)
                        {
                            MACBuf = HMAC.ComputeHash(MACBuf);
                            for (int k = 0; k < Buf.Length; k++)
                                Buf[k] ^= MACBuf[k];
                        }

                        Strm.Write(Buf, 0, Buf.Length);
                    }

                    return Strm.ToArray();
                }
            }
        }
    }
}