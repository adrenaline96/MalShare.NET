using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace MalShare.NET
{
    public class MSClient
    {
        private string key;

        public MSClient(string apiKey)
        {
            key = apiKey;
        }

        public List<string> Search(string searchQuery)
        {
            List<string> searchResults = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=search&query={searchQuery}";

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AutomaticDecompression = DecompressionMethods.GZip;
            request.Timeout = 5000;

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
            }
            catch { }

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
                searchResults.Add($"Results for {searchQuery}: Not found.");
            }


            return searchResults;
        }

        public List<string> SearchByType(string type)
        {
            List<string> searchResults = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=type&type={type}";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
            }
            catch { }
            dynamic dynObj = JsonConvert.DeserializeObject(html);

            if (html != "[]" && !String.IsNullOrWhiteSpace(html))
            {
                foreach (var item in dynObj)
                {
                    searchResults.Add("MD5: " + item.md5 + "/SHA1: " + item.sha1 + "/SHA256: " + item.sha256);
                }
            }
            else
            {
                searchResults.Add($"Results for {type}: Not found.");
            }

            return searchResults;
        }

        public List<string> GetDetails(string hash)
        {
            List<string> searchResults = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=details&hash={hash}";

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
                //404 not found
            }
            dynamic dynObj = JsonConvert.DeserializeObject(html);

            if (!String.IsNullOrEmpty(html))
            {
                searchResults.Add("MD5: " + dynObj.MD5);
                searchResults.Add("SHA1: " + dynObj.SHA1);
                searchResults.Add("SHA256: " + dynObj.SHA256);
                searchResults.Add("SSDEEP: " + dynObj.SSDEEP);
                searchResults.Add("Type: " + dynObj.F_TYPE);
                foreach (var item in dynObj.SOURCES)
                {
                    searchResults.Add("Source: " + Convert.ToString(item));
                }
            }
            else
            {
                searchResults.Add($"Results for {hash}: Not found.");
            }

            return searchResults;
        }

        public List<string> GetTypeList()
        {
            List<string> types = new List<string>();


            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=gettypes";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }

            }
            catch
            {
                types.Add("Failed to retreive list.");
            }

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);


                foreach (var item in dynObj)
                {
                    types.Add(Convert.ToString(item).Replace("\"", String.Empty));
                }
                types.RemoveAll(String.IsNullOrWhiteSpace);
            }
            return types;
        }

        public List<string> GetSources()
        {
            List<string> sources = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getsources";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
            }
            catch
            {
                sources.Add("Failed to retrieve sources.");
            }

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                foreach (var item in dynObj)
                {
                    sources.Add(Convert.ToString(item));
                }
                sources.RemoveAll(String.IsNullOrWhiteSpace);
            }

            return sources;
        }

        public List<string> GetHashList()
        {
            List<string> hashList = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getlist";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
            }
            catch
            {
                hashList.Add("Failed to retrive hash list.");
            }

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                foreach (var item in dynObj)
                {
                    hashList.Add("MD5: " + item.md5 + "/SHA1: " + item.sha1 + "/SHA256: " + item.sha256);
                }
            }
            return hashList;
        }

        public List<string> GetRequestLimit()
        {
            List<string> limitList = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getlimit";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }

            }
            catch
            {
                limitList.Add("Failed to retrieve request limit.");
            }

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                limitList.Add("Limit: " + dynObj.LIMIT);
                limitList.Add("Remaining: " + dynObj.REMAINING);

            }
            return limitList;
        }

        public string Upload(string filePath)
        {
            WebClient wc = new WebClient();

            string url = $@"https://malshare.com/api.php?api_key={key}&action=upload";

            try
            {
                wc.UploadFile(url, filePath);

                wc.Dispose();

            }
            catch
            {
                return $"{filePath} - Failed to upload file.";
            }

            return $"File {filePath} uploaded successfully.";
        }

        public string DownloadFile(string hash)
        {
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getfile&hash={hash}";

            Directory.CreateDirectory("DownloadedFiles");

            WebClient client = new WebClient();
            try
            {
                client.DownloadFile(new Uri(url), @"DownloadedFiles\" + hash);
            }
            catch
            {
                return $"File with hash {hash} not found.";
            }

            return $@"File with hash {hash} downloaded to DownloadedFiles\{hash}";

        }

        public string UrlToCollection(string urlToUpload)
        {
            string url = $@"https://malshare.com/api.php?api_key={key}&action=download_url";

            string responseStr = String.Empty;

            using (WebClient wb = new WebClient())
            {
                try
                {
                    NameValueCollection data = new NameValueCollection();
                    data["url"] = urlToUpload;


                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);


                    dynamic dynObj = JsonConvert.DeserializeObject(responseInString);

                    responseStr = $"GUID for {urlToUpload}: {dynObj.guid}";

                }
                catch (WebException ex)
                {
                    if (ex.Response != null)
                    {
                        var response = ex.Response;
                        var dataStream = response.GetResponseStream();
                        var reader = new StreamReader(dataStream);
                        var details = reader.ReadToEnd();

                        return details;
                    }
                }
                catch
                {
                    return $"Failed to add {urlToUpload} to the sample collection.";
                }

                return responseStr;
            }

        }

        public string CheckGUID(string guid)
        {
            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=download_url_check&guid={guid}";

            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }

            }
            catch
            {
                return $"Failed to retrieve status for {guid}";
            }

            dynamic dynObj = JsonConvert.DeserializeObject(html);


            return $"Status for {guid}: {dynObj.status}";
        }
    }

}
