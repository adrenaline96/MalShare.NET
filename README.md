# MalShare.NET
A .NET implementation of the MalShare API
<br>MalShare.com is a free malware repository providing researchers access to samples, malicous feeds, and Yara results.


What's currently supported (https://malshare.com/doc.php):
1. List hashes from the past 24 hours. **Endpoint: "getlist"**.
2. List of sample sources from the past 24 hours. **Endpoint: "getsources".**
3. Get stored file details. **Endpoint: "details".**
4. List MD5/SHA1/SHA256 hashes of a specific type from the past 24 hours. **Endpoint: "type".**
5. Search sample hashes, sources and file names. **Endpoint: "search".**
6. Upload using FormData field "upload". **Endpoint: "upload".**
7. Get list of file types & count from the past 24 hours. **Endpoint: "gettypes".**
8. GET allocated number of API key requests per day and remaining. **Endpoint: "getlimit".**
9. Download file. **Endpoint: "getfile".**
10. Perform URL download and add result to sample collection. **Endpoint: "download_url".**
11. Check status of download task via GUID. **Endpoint: "download_url_check".**
12. **NEW in version 2.3**: Partial support for "Supply an array of hex-encoded hashes in a POST field named hashes". Right now you can supply **only 1 hash per call**, you **can't supply an array.** **Endpoint: "hashlookup".**

How to install:

You have 3 options:
1. Add reference to the .dll file in your project, you will need to add the NewtonSoft.Json dependency **yourself**
2. Install the NuGet Package from nuget.org (https://www.nuget.org/packages/MalShare.NET)
3. Install the .nupkg file manually

Dependencies:
1. Microsoft.CSharp (>= 4.7.0)
2. Newtonsoft.Json (>= 12.0.3)
3. NETStandard.Library (>= 2.0.3)

How to use:

You can find usage examples and explanations for each endpoint here: https://pastebin.com/8n61zvas
