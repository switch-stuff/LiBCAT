using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace LiBCAT
{
    internal class Crypto
    {
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

        internal static readonly byte[] RetailRSAModulo =
        {
            0xBB, 0x4E, 0x9D, 0x60, 0x01, 0x4B, 0x3D, 0x3B,
            0x78, 0xE8, 0x0B, 0x26, 0x7D, 0xD7, 0xBB, 0xC2,
            0xD8, 0x66, 0x7E, 0x48, 0x7D, 0xC4, 0x23, 0x69,
            0xEA, 0x60, 0x6A, 0xC6, 0xE1, 0xD1, 0x22, 0xDE,
            0xB1, 0x46, 0xF3, 0xE5, 0x4D, 0x49, 0x87, 0x3D,
            0x5F, 0xF4, 0xF7, 0x92, 0xA5, 0x87, 0x50, 0x07,
            0x9D, 0xF2, 0x8A, 0xAD, 0xE7, 0x0B, 0x5B, 0x33,
            0x22, 0x49, 0x53, 0x69, 0xF1, 0x8B, 0xDE, 0x51,
            0xED, 0xE1, 0xC4, 0xB2, 0xF1, 0xA2, 0x98, 0x29,
            0x10, 0xF8, 0x37, 0x22, 0x0F, 0x44, 0x18, 0x02,
            0xB8, 0x49, 0xA1, 0x92, 0x34, 0x1E, 0xD8, 0xFF,
            0xC6, 0x8A, 0x4D, 0x4B, 0xD6, 0x55, 0x5E, 0x14,
            0xC2, 0x7C, 0x80, 0x2B, 0xF8, 0xC0, 0x07, 0xCC,
            0x7D, 0x69, 0x96, 0xED, 0x5C, 0xA9, 0x2D, 0xEC,
            0x5D, 0x6F, 0xCF, 0x45, 0xFC, 0x04, 0xD6, 0x04,
            0xCE, 0xCC, 0x9A, 0xF1, 0x9B, 0x28, 0xF3, 0x6E,
            0xAF, 0x95, 0xDF, 0x90, 0x99, 0x47, 0x59, 0xD3,
            0x08, 0xE7, 0xDD, 0x45, 0xF9, 0xC7, 0xA6, 0x40,
            0x9C, 0x39, 0xDC, 0x9D, 0x9C, 0x32, 0x5A, 0xD4,
            0xCB, 0x73, 0xCF, 0x76, 0x3F, 0x21, 0x17, 0x7E,
            0xE2, 0x5B, 0x56, 0x05, 0x10, 0x10, 0xA0, 0xA3,
            0x10, 0x6F, 0x2B, 0x66, 0xA7, 0xC4, 0x34, 0xC9,
            0xCE, 0x22, 0x45, 0x44, 0x80, 0x33, 0x4F, 0x52,
            0x80, 0xE7, 0xE6, 0x64, 0x1D, 0x18, 0xF4, 0x3E,
            0xB0, 0xF3, 0xCE, 0x65, 0x5B, 0x9C, 0xDD, 0xF6,
            0x87, 0xEC, 0xDD, 0xB3, 0xF0, 0x14, 0xC2, 0x9B,
            0xAB, 0xC3, 0xE8, 0x73, 0x4D, 0xD4, 0x49, 0x5A,
            0xF1, 0xBB, 0x07, 0xA9, 0xC4, 0xF3, 0x61, 0x25,
            0xDD, 0x9F, 0xA6, 0x64, 0x46, 0xC8, 0xC7, 0xF1,
            0x10, 0xB3, 0x0B, 0x41, 0x3E, 0x3D, 0x76, 0x66,
            0xD1, 0x01, 0xC9, 0x50, 0x34, 0x6A, 0x14, 0x11,
            0x68, 0x46, 0xD7, 0x72, 0x47, 0x3E, 0xBF, 0x89
        };

        internal static readonly byte[] DevRSAModulo = 
        {
            0xB3, 0x02, 0x96, 0x6F, 0x8A, 0x1F, 0x9E, 0xF5, 0x37, 0xC8, 0xEA, 0x25,
            0xCD, 0x50, 0x86, 0xD9, 0x2A, 0x14, 0x8A, 0x27, 0x65, 0xAA, 0xCE, 0xAF,
            0x32, 0x82, 0x2D, 0x8C, 0x1C, 0x61, 0xD2, 0x16, 0x76, 0x4D, 0x82, 0xEB,
            0xB2, 0x6A, 0x8B, 0x7A, 0x29, 0x69, 0xAE, 0x3C, 0x55, 0x61, 0x9B, 0x2B,
            0x62, 0x08, 0x30, 0x77, 0x4E, 0x89, 0x03, 0x68, 0xEF, 0xA8, 0xEE, 0xDE,
            0x5B, 0xA9, 0x2B, 0x60, 0x08, 0x1B, 0x80, 0x6C, 0x57, 0x64, 0xD1, 0x45,
            0x7A, 0xF2, 0x18, 0xA0, 0x18, 0x4A, 0x68, 0xB5, 0x74, 0x6C, 0xD9, 0x21,
            0x1B, 0xE5, 0x8C, 0x06, 0x1F, 0x84, 0x06, 0x0F, 0x09, 0x54, 0x2B, 0x28,
            0x2B, 0xD9, 0xB6, 0x22, 0x96, 0x83, 0x50, 0x38, 0x29, 0xC2, 0xE4, 0x0A,
            0x45, 0xC3, 0x9B, 0x63, 0xD6, 0xD2, 0x47, 0xC7, 0x46, 0x1E, 0x61, 0xF7,
            0x6C, 0xE2, 0x16, 0xBB, 0x9A, 0x83, 0x91, 0xE5, 0x91, 0xA2, 0x2D, 0x6A,
            0x99, 0x85, 0x09, 0x00, 0xDC, 0x89, 0x11, 0x3F, 0x9C, 0xB0, 0x3E, 0xD3,
            0x55, 0x28, 0xF2, 0x6B, 0x7D, 0x04, 0xB7, 0xA1, 0xEF, 0x02, 0xB7, 0xC0,
            0x1B, 0x33, 0xF5, 0x4E, 0xB2, 0x67, 0xF0, 0x0D, 0x76, 0xD6, 0x3D, 0x64,
            0x02, 0x5D, 0x88, 0x7F, 0x57, 0xD1, 0x3B, 0xC8, 0x37, 0x53, 0x8B, 0x66,
            0x15, 0xDA, 0xAF, 0x55, 0x6A, 0x70, 0xE0, 0x9F, 0xE2, 0x7C, 0xC1, 0xD5,
            0xEB, 0xDB, 0x1E, 0xB0, 0x00, 0x6C, 0x2B, 0x1A, 0xD8, 0x96, 0xC2, 0xBE,
            0x86, 0xD9, 0x02, 0x9F, 0xD1, 0xA7, 0x12, 0x6E, 0xFB, 0x3E, 0x6C, 0x7B,
            0x49, 0x11, 0x4F, 0x8E, 0x94, 0x5D, 0xC3, 0xAC, 0xD8, 0xA4, 0x07, 0x2C,
            0xC4, 0x5E, 0x30, 0xAA, 0x35, 0xA9, 0x15, 0x34, 0x1D, 0xAB, 0xA7, 0x84,
            0xF4, 0x4C, 0xA0, 0xC1, 0xFE, 0x92, 0xCE, 0xAF, 0x0C, 0x92, 0x91, 0xED,
            0xEC, 0xEB, 0xDD, 0x0B
        };

        internal static readonly byte[] RSAExponent = { 0, 1, 0, 1 };

        internal static RSAParameters Params(bool isRetail)
        {
            if (isRetail) return new RSAParameters()
            {
                Exponent = RSAExponent,
                Modulus = RetailRSAModulo
            };
            else return new RSAParameters()
            {
                Exponent = RSAExponent,
                Modulus = DevRSAModulo
            };
        }

        public static byte[] GetBcatData(string Url)
        {
            ServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => true;
            using (var Cli = new WebClient()) return Cli.DownloadData(Url);
        }

        public static byte[] DecryptBcatData(byte[] Data, ulong TitleID, byte[] Passphrase, bool isRetail = true)
        {
            HashAlgorithmName Name;
            RSASignaturePadding Pad;

            using (MemoryStream Strm = new MemoryStream(Data))
            using (BinaryReader Rd = new BinaryReader(Strm))
            {
                if (Rd.ReadUInt32() != 0x74616362)
                    throw new InvalidDataException("Error: This is not a BCAT file!");

                Strm.Position++;

                var KeySize = (Rd.ReadByte() + 1) << 3;

                switch (Rd.ReadByte())
                {
                    case 0:
                        Name = HashAlgorithmName.SHA1;
                        Pad = RSASignaturePadding.Pkcs1;
                        break;

                    case 1:
                        Name = HashAlgorithmName.SHA256;
                        Pad = RSASignaturePadding.Pkcs1;
                        break;

                    case 2:
                        Name = HashAlgorithmName.SHA1;
                        Pad = RSASignaturePadding.Pss;
                        break;

                    case 3:
                        Name = HashAlgorithmName.SHA256;
                        Pad = RSASignaturePadding.Pss;
                        break;

                    default:
                        throw new InvalidDataException("Error: Unsupported RSA type!");
                }

                var Index = Rd.ReadByte();

                Strm.Position += 8;

                var IV = Rd.ReadBytes(0x10);
                var Signature = Rd.ReadBytes(0x100);
                var EncData = Rd.ReadBytes((int)(Strm.Length - 0x120));

                using (var Rsa = new RSACng())
                {
                    byte[] Salt;

                    Rsa.ImportParameters(Params(isRetail));

                    if (isRetail) Salt = $"{TitleID:x16}{Salts[Index]}".TBA();
                    else Salt = $"{TitleID:x16}".TBA();

                    var DecData = Aes.CTR(EncData, PBKDF2(KeySize, Passphrase, Salt, 4096), IV);

                    if (!Rsa.VerifyData(DecData, Signature, Name, Pad))
                        throw new InvalidDataException("Error: BCAT data has a bad signature!");

                    return DecData;
                }
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

        private static class Aes
        {
            public static byte[] CTR(byte[] Data, byte[] Key, byte[] IV)
            {
                var Aes = new AesCryptoServiceProvider()
                {
                    Key = Key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                }
                .CreateEncryptor();

                var Len = Data.Length;
                byte[] OutBuf = new byte[Len], KeyBuf = new byte[16];

                for (int i = 0; i < Len; i += 16)
                {
                    KeyBuf = Aes.TransformFinalBlock(IV, 0, IV.Length);

                    var Ptr = Len - i;

                    if (Ptr > 16) Ptr = 16;

                    for (int j = 0; j < Ptr; j++)
                        OutBuf[i + j] = (byte)(KeyBuf[j] ^ Data[i + j]);

                    for (var j = 15; j >= 0; j--)
                        if (++IV[j] != 0) break;
                }

                return OutBuf;
            }
        }

    }
}