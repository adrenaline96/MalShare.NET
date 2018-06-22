# MalShare.NET
A .NET implementation of the MalShare API
<br>MalShare.com is a free malware repository providing researchers access to samples, malicous feeds, and Yara results.


What's currently supported (https://malshare.com/doc.php):
<br>List hashes from the past 24 hours
<br>List of sample sources from the past 24 hours
<br>Get stored file details
<br>List MD5/SHA1/SHA256 hashes of a specific type from the past 24 hours
<br>Search sample hashes, sources and file names
<br>Upload using FormData field "upload"
<br>Get list of file types & count from the past 24 hours
<br>GET allocated number of API key requests per day and remaining

How to install:

You have 3 options:
1. Add reference to the .dll file in your project
2. Install the NuGet Package from nuget.org (https://www.nuget.org/packages/MalShare.NET)
3. Install the .nupkg file manually

Dependencies:
1. Microsoft.CSharp (>= 4.5.0)
2. Newtonsoft.Json (>= 11.0.2)
3. NETStandard.Library (>= 2.0.1)

How to use:

You can find usage examples here: https://pastebin.com/8n61zvas
