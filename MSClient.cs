using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace MalShare.NET
{
    public class MSClient
    {
        private String key;

       public MSClient(String apiKey)
        {
            key = apiKey;
        }

        public List<String> Search(String searchQuery)
        {
            List<String> searchResults = new List<String>();

            String html = String.Empty;
            String url = @"https://malshare.com/api.php?api_key=" + key + "&action=search&query=" + searchQuery;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                html = reader.ReadToEnd();
            }

            if (!String.IsNullOrEmpty(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                searchResults.Add("MD5: " + dynObj.md5);
                searchResults.Add("SHA1: " + dynObj.sha1);
                searchResults.Add("SHA256: " + dynObj.sha256);
                searchResults.Add("Type: " + dynObj.type);
                searchResults.Add("Added: " + dynObj.added);
                searchResults.Add("Source: " + dynObj.source);

                foreach (var item in dynObj.yarahits.yara)
                {
                    searchResults.Add("Yara: " + item);
                }

                if (!String.IsNullOrWhiteSpace(dynObj.yarahits.parentfiles))
                {
                    searchResults.Add("Parent Files: " + dynObj.yarahits.parentfiles);
                }
                if (!String.IsNullOrWhiteSpace(dynObj.yarahits.subfiles))
                {
                    searchResults.Add("Sub Files: " + dynObj.yarahits.subfiles);
                }
            }
            else
            {
                searchResults.Add("Not found.");
            }


            return searchResults;
        }

        public List<String> SearchByType(String type)
        {
            List<String> searchResults = new List<String>();

            String html = String.Empty;
            String url = @"https://malshare.com/api.php?api_key=" + key + "&action=type&type=" + type;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                html = reader.ReadToEnd();
            }

            dynamic dynObj = JsonConvert.DeserializeObject(html);

            if (html != "[]")
            {
                foreach (var item in dynObj)
                {
                    searchResults.Add("MD5: " + item.md5 + "/SHA1: " + item.sha1 + "/SHA256: " + item.sha256);
                }
            }
            else
            {
                searchResults.Add("Not found.");
            }

            return searchResults;
        }

        public List<String> GetDetails(String hash)
        {
            List<String> searchResults = new List<String>();

            String html = String.Empty;
            String url = @"https://malshare.com/api.php?api_key=" + key + "&action=details&hash=" + hash;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
            }
            catch
            {
                //if you search for a nonexistent hash it gives a 500 internal server error
            }
            dynamic dynObj = JsonConvert.DeserializeObject(html);

            if (!String.IsNullOrEmpty(html))
            {
                searchResults.Add("MD5: " + dynObj.MD5);
                searchResults.Add("SHA1: " + dynObj.SHA1);
                searchResults.Add("SHA256: " + dynObj.SHA256);
                searchResults.Add("SSDEEP: " + dynObj.SSDEEP);
                searchResults.Add("Type: " + dynObj.F_TYPE);
                searchResults.Add("Sources: " + dynObj.SOURCES); //there's an issue with MalShare, poorly parsed JSON
            }
            else
            {
                searchResults.Add("Not found.");
            }

                return searchResults;
        }

        public List<String> GetSources()
        {
            List<String> sources = new List<String>();

            String html = String.Empty;
            String url = @"https://malshare.com/api.php?api_key=" + key + "&action=getsources";

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                html = reader.ReadToEnd();
            }

            dynamic dynObj = JsonConvert.DeserializeObject(html);

            foreach (var item in dynObj)
            {
                sources.Add(item);
            }
            sources.RemoveAll(string.IsNullOrWhiteSpace);

            return sources;
        }

        public List<String> GetHashList()
        {
            List<String> hashList = new List<String>();

            String html = String.Empty;
            String url = @"https://malshare.com/api.php?api_key=" + key + "&action=getlist";

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                html = reader.ReadToEnd();
            }

            dynamic dynObj = JsonConvert.DeserializeObject(html);

            foreach (var item in dynObj)
            {
                hashList.Add("MD5: " + item.md5 + "/SHA1: " + item.sha1 + "/SHA256: " + item.sha256);
            }

            return hashList;
        }

        public void Upload(String filePath)
        {
            WebClient wc = new WebClient();

            string url = @"https://malshare.com/api.php?api_key=" + key + "&action=upload";

            wc.UploadFile(url, filePath);

            wc.Dispose();

        }
    }
}
