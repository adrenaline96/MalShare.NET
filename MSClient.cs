using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Text;

namespace MalShare.NET
{
    public class MSClient
    {
        private string key;

        public MSClient(string apiKey)
        {
            key = apiKey;
        }

        private static string GetResponse(string url)
        {
            string html = String.Empty;

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

            return html;
        }
        public List<string> Search(string searchQuery)
        {
            List<string> searchResults = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=search&query={searchQuery}";


            html = GetResponse(url);

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


            html = GetResponse(url);


            if (html != "[]" && !String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);
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

            html = GetResponse(url);

            if (!String.IsNullOrEmpty(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

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


            html = GetResponse(url);

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);


                foreach (var item in dynObj)
                {
                    types.Add(Convert.ToString(item).Replace("\"", String.Empty));
                }
                types.RemoveAll(String.IsNullOrWhiteSpace);
            }
            else
            {
                types.Add("Failed to retreive list.");
            }
            return types;
        }

        public List<string> GetSources()
        {
            List<string> sources = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getsources";

            html = GetResponse(url);

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                foreach (var item in dynObj)
                {
                    sources.Add(Convert.ToString(item));
                }
                sources.RemoveAll(String.IsNullOrWhiteSpace);
            }
            else
            {
                sources.Add("Failed to retrieve sources.");
            }

            return sources;
        }

        public List<string> GetHashList()
        {
            List<string> hashList = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getlist";


            html = GetResponse(url);

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                foreach (var item in dynObj)
                {
                    hashList.Add("MD5: " + item.md5 + "/SHA1: " + item.sha1 + "/SHA256: " + item.sha256);
                }
            }
            else
            {
                hashList.Add("Failed to retrive hash list.");
            }
            return hashList;
        }

        public List<string> GetRequestLimit()
        {
            List<string> limitList = new List<string>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=getlimit";


            html = GetResponse(url);

            if (!String.IsNullOrWhiteSpace(html))
            {
                dynamic dynObj = JsonConvert.DeserializeObject(html);

                limitList.Add("Limit: " + dynObj.LIMIT);
                limitList.Add("Remaining: " + dynObj.REMAINING);

            }
            else
            {
                limitList.Add("Failed to retrieve request limit.");
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

        public string UrlToCollection(string urlToUpload, bool enableCrawling = false)
        {
            string url = $@"https://malshare.com/api.php?api_key={key}&action=download_url";

            string responseStr = String.Empty;

            using (WebClient wb = new WebClient())
            {
                try
                {
                    NameValueCollection data = new NameValueCollection();
                    data["url"] = urlToUpload;
                    if(enableCrawling == true)
                    {
                        data["recursive"] = "1";
                    }

                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);


                    dynamic dynObj = JsonConvert.DeserializeObject(responseInString);

                    responseStr = $"GUID for {urlToUpload}: {dynObj.guid}";

                }
                catch (WebException ex)
                {
                    if (ex.Response != null)
                    {
                        WebResponse response = ex.Response;
                        Stream dataStream = response.GetResponseStream();
                        StreamReader reader = new StreamReader(dataStream);
                        string details = reader.ReadToEnd();

                        if (details.Contains("error"))
                        {
                            dynamic dynObj = JsonConvert.DeserializeObject(details);

                            return $"Error for API key {key}: {dynObj.error}";
                        }

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

            html = GetResponse(url);
            if (String.IsNullOrWhiteSpace(html))
            {
                return $"Failed to retrieve status for {guid}";
            }

            dynamic dynObj = JsonConvert.DeserializeObject(html);
            
            return $"Status for {guid}: {dynObj.status}";
        }

        public string HashLookup(string hash)
        {
            string url = $@"https://malshare.com/api.php?api_key={key}&action=hashlookup";

            string responseStr = String.Empty;

            using (WebClient wb = new WebClient())
            {
                try
                {

                    var response = wb.UploadString(url, "POST", hash);

                    var result = JsonConvert.DeserializeObject<List<Hashes>>(response);

                    responseStr = $"MD5: {result[0].md5}/SHA1: {result[0].sha1}/SHA256: {result[0].sha256}";


                }
                catch (WebException ex)
                {
                    if (ex.Response != null)
                    {
                        WebResponse response = ex.Response;
                        Stream dataStream = response.GetResponseStream();
                        StreamReader reader = new StreamReader(dataStream);
                        string details = reader.ReadToEnd();

                        if (details.Contains("error"))
                        {
                            dynamic dynObj = JsonConvert.DeserializeObject(details);

                            return $"Error for API key {key}: {dynObj.error}";
                        }

                        return details;
                    }
                }
                catch
                {
                    return $"Failed to retrieve data for {hash}. Perhaps it doesn't exist in the database.";
                }

                return responseStr;
            }
        }
    }

    public class Hashes
    {
        public string md5 { get; set; }
        public string sha1 { get; set; }
        public string sha256 { get; set; }
    }
}
