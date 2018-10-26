using MessagePack;
using System.Text;

namespace LiBCAT
{
    /// <summary>
    /// The base class.
    /// </summary>
    public static class Bcat
    {
        /// <summary>
        /// The passphrase used for news decryption.
        /// </summary>
        public static readonly byte[] NewsPassphrase =
        {
            0x61, 0x63, 0x64, 0x61, 0x33, 0x35, 0x38, 0x62,
            0x34, 0x64, 0x33, 0x32, 0x64, 0x31, 0x37, 0x66,
            0x64, 0x34, 0x30, 0x33, 0x37, 0x63, 0x31, 0x62,
            0x35, 0x65, 0x30, 0x32, 0x33, 0x35, 0x34, 0x32,
            0x37, 0x61, 0x38, 0x35, 0x36, 0x33, 0x66, 0x39,
            0x33, 0x62, 0x30, 0x66, 0x64, 0x62, 0x34, 0x32,
            0x61, 0x34, 0x61, 0x35, 0x33, 0x36, 0x65, 0x65,
            0x39, 0x35, 0x62, 0x62, 0x66, 0x38, 0x30, 0x66
        };

        /// <summary>
        /// QLaunch's title ID, used for news.
        /// </summary>
        public const ulong QLaunchTID = 0x100000000001000;

        internal static byte[] TBA(this string Input) => Encoding.ASCII.GetBytes(Input);

        /// <summary>
        /// Gets the news article JSON from the specified URL.
        /// </summary>
        /// <param name="URL">The target URL.</param>
        /// <param name="AsJson">Whether to return it as raw data or a Json.</param>
        /// <param name="TID">The target title ID.</param>
        /// <param name="Passphrase">The target title's passphrase.</param>
        /// <returns>The news article JSON as a string.</returns>
        public static object GetData(string URL, bool AsJson, ulong TID, string Passphrase)
        {
            var BcatFile =
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData(URL),
                TID,
                Encoding.ASCII.GetBytes(Passphrase)
            );

            if (AsJson) return MessagePackSerializer.ToJson(BcatFile);
            else return BcatFile;
        }

        /// <summary>
        /// Provides a wrapper for the BCAT news API.
        /// </summary>
        public static class News
        {
            /// <summary>
            /// A structure containing the target language and country.
            /// </summary>
            public struct Region
            {
                /// <summary>
                /// A language; see the Languages class for a list.
                /// </summary>
                public string Language;

                /// <summary>
                /// A country; see the Countries class for a list.
                /// </summary>
                public string Country;
            }

            /// <summary>
            /// Countries news is available in.
            /// </summary>
            public static class Countries
            {
                public const string Australia = "AU";
                public const string Austria = "AT";
                public const string Belgium = "BE";
                public const string Brazil = "BR";
                public const string Canada = "CA";
                public const string CzechRepublic = "CZ";
                public const string Denmark = "DK";
                public const string Finland = "FI";
                public const string France = "FR";
                public const string Germany = "DE";
                public const string HongKong = "HK";
                public const string Hungary = "HU";
                public const string Ireland = "IE";
                public const string Italy = "IT";
                public const string Japan = "JP";
                public const string Mexico = "MX";
                public const string Netherlands = "NL";
                public const string NewZealand = "NZ";
                public const string Norway = "NO";
                public const string Poland = "PL";
                public const string Portugal = "PT";
                public const string Russia = "RU";
                public const string SouthAfrica = "ZA";
                public const string SouthKorea = "KR";
                public const string Spain = "ES";
                public const string Sweden = "SE";
                public const string Switzerland = "CH";
                public const string UnitedKingdom = "GB";
                public const string UnitedStates = "US";
            }

            /// <summary>
            /// Languages news is available in.
            /// </summary>
            public static class Languages
            {
                public const string Japanese = "ja";
                public const string AmericanEnglish = "en-US";
                public const string French = "fr";
                public const string German = "de";
                public const string Italian = "it";
                public const string Spanish = "es";
                public const string Chinese = "zh-CN";
                public const string Korean = "ko";
                public const string Dutch = "nl";
                public const string Portuguese = "pt";
                public const string Russian = "ru";
                public const string Taiwanese = "zh-TW";
                public const string BritishEnglish = "en-GB";
                public const string CanadianFrench = "fr-CA";
                public const string LatinAmericanSpanish = "es-419";
                public const string SimplifiedChinese = "zh-Hans";
                public const string TraditionalChinese = "zh-Hant";
            }

            /// <summary>
            /// Returns the Nintendo News list for the specified region.
            /// </summary>
            /// <param name="Reg">A Region struct.</param>
            /// <returns>Nintendo News list JSON as a string.</returns>
            public static string GetNxNewsList(Region Reg) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData($"https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/nx_news?l={Reg.Language}&c[]={Reg.Country}"),
                QLaunchTID,
                NewsPassphrase
            ));

            /// <summary>
            /// Returns the news list for a specified region and topic ID.
            /// </summary>
            /// <param name="Reg">A Region struct.</param>
            /// <param name="TopicID">The topic ID for the title you wish to retrieve news for.</param>
            /// <returns>News list JSON as a string.</returns>
            public static string GetNewsList(Region Reg, string TopicID) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData($"https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/{TopicID}?l={Reg.Language}&c[]={Reg.Country}"),
                QLaunchTID,
                NewsPassphrase
            ));

            /// <summary>
            /// Gets the topics for a specified title ID.
            /// </summary>
            /// <param name="Reg">A Region struct.</param>
            /// <param name="TitleID">The title ID of the game you wish to retrieve news for.</param>
            /// <returns>The topics list JSON as a string.</returns>
            public static string GetTopics(Region Reg, ulong TitleID) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData($"https://bcat-topics-lp1.cdn.nintendo.net/api/nx/v1/titles/{TitleID:x16}/topics?l={Reg.Language}&c[]={Reg.Country}"),
                QLaunchTID,
                NewsPassphrase
            ));

            /// <summary>
            /// Gets the news catalog for a specified region.
            /// </summary>
            /// <param name="Reg">A Region struct.</param>
            /// <returns>The catalog JSON as a string.</returns>
            public static string GetCatalog(Region Reg) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData($"https://bcat-topics-lp1.cdn.nintendo.net/api/nx/v1/topics/catalog?l={Reg.Language}&c[]={Reg.Country}"),
                QLaunchTID,
                NewsPassphrase
            ));
        }

        /// <summary>
        /// Provides a wrapper for the BCAT data API.
        /// </summary>
        public static class Data
        {
            /// <summary>
            /// Gets the BCAT data for a specified title ID.
            /// </summary>
            /// <param name="TitleID">The target title ID.</param>
            /// <param name="Passphrase">The passphrase for the target title.</param>
            /// <returns></returns>
            public static string GetNxData(ulong TitleID, string Passphrase) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData($"https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/nx_data_{TitleID:x16}"),
                TitleID,
                Encoding.ASCII.GetBytes(Passphrase)
            ));
        }
    }
}