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
            request.Timeout = 30000;

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
        public List<List<string>> Search(string searchQuery)
        {
            List<List<string>> searchResults = new List<List<string>>();

            string html = String.Empty;
            string url = $@"https://malshare.com/api.php?api_key={key}&action=search&query={searchQuery}";

            html = GetResponse(url);

            if (!String.IsNullOrEmpty(html))
            {
                var result = JsonConvert.DeserializeObject<List<Search>>(html);
                foreach (var res in result)
                {
                    StringBuilder yara = new StringBuilder("Yara Hits: ");
                    StringBuilder parentfiles = new StringBuilder("Parent Files: ");
                    StringBuilder subfiles = new StringBuilder("Sub Files: ");

                    if (res.yarahits.yara.Count == 0)
                    {
                        yara.Append("-");
                    }
                    else
                    {
                        yara.Append(String.Join(", ", res.yarahits.yara));
                    }
                    if (res.parentfiles.Count == 0)
                    {
                        parentfiles.Append("-");
                    }
                    else
                    {
                        parentfiles.Append(String.Join(", ", res.parentfiles));
                    }
                    if (res.subfiles.Count == 0)
                    {
                        subfiles.Append("-");
                    }
                    else
                    {
                        subfiles.Append(String.Join(", ", res.subfiles));
                    }

                    searchResults.Add(new List<string> { $"MD5: {res.md5}", $"SHA1: {res.sha1}", $"SHA256: {res.sha256}", $"Type: {res.type}", $"Added: {res.added}", $"Source: {res.source}", yara.ToString(), parentfiles.ToString(), subfiles.ToString() });
                }
            }
            else
            {
                searchResults.Add(new List<string> { $"Results for {searchQuery}: Not found." });
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
    public class Search
    {
        public string md5 { get; set; }
        public string sha1 { get; set; }
        public string sha256 { get; set; }
        public string type { get; set; }
        public string added { get; set; }
        public string source { get; set; }
        public Yarahits yarahits { get; set; }
        public List<string> parentfiles { get; set; }
        public List<string> subfiles { get; set; }
    }
    public class Yarahits
    {
        public List<string> yara { get; set; }
    }
}
