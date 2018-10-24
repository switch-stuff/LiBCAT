using MessagePack;
using System.Text;

namespace LiBCAT
{
    public static class Bcat
    {
        internal static byte[] TBA(this string Input) => Encoding.ASCII.GetBytes(Input);

        public static class News
        {
            private const string NewsPassphrase = "acda358b4d32d17fd4037c1b5e0235427a8563f93b0fdb42a4a536ee95bbf80f";
            private const ulong QLaunchTID = 0x100000000001000;

            /// <summary>
            /// A structure containing the target language and country.
            /// </summary>
            public struct Region
            {
                public string Language;
                public string Country;
            }

            /// <summary>
            /// Some of the available news countries.
            /// </summary>
            public static class Countries
            {
                public const string AusNZ = "AU";
                public const string Americas = "US";
                public const string Europe = "GB";
                public const string Japan = "JP";
                public const string HongKong = "HK";
            }

            /// <summary>
            /// Some of the available news languages.
            /// </summary>
            public static class Languages
            {
                public const string EnglishUS = "en-US";
                public const string EnglishUK = "en-GB";
                public const string French = "fr-FR";
                public const string Spanish = "es-ES";
                public const string Italian = "it-IT";
                public const string German = "de-DE";
                public const string Japanese = "ja-JP";
                public const string Chinese = "zh-HK";
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
                NewsPassphrase,
                true
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
                NewsPassphrase,
                true
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
                NewsPassphrase,
                true
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
                NewsPassphrase,
                true
            ));

            /// <summary>
            /// Gets the news article JSON from the specified URL.
            /// </summary>
            /// <param name="URL">The target URL.</param>
            /// <returns>The news article JSON as a string.</returns>
            public static string GetNews(string URL) => MessagePackSerializer.ToJson(
            Crypto.DecryptBcatData
            (
                Crypto.GetBcatData(URL),
                QLaunchTID,
                NewsPassphrase,
                true
            ));
        }

        public static class Data
        {
        }
    }
}