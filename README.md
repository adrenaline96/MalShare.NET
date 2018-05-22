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

How to install:

You have 3 options:
1. Add reference to the .dll file in your project
2. Install the NuGet Package from nuget.org (https://www.nuget.org/packages/MalShare.NET)
3. Install the .nupkg file manually


How to use:

After installing the package, add the next line:
using MalShare.NET;

After that, you are rolling...

MSClient msc = new MSClient("<<API KEY>>");

List<String> searchResults = new List<String>();

searchResults.AddRange(msc.Search("<query>")); //Retrieves file information by searching sample hashes, sources and file names

searchResults.AddRange(msc.SearchByType("<type>")); //Retrieves a list of MD5/SHA1/SHA256 hashes of a specific type from the past 24 hours

searchResults.AddRange(msc.GetDetails("MD5/SHA1/SHA256 hash")); //Get stored file details

searchResults.AddRange(msc.GetSources()); //List of sample sources from the past 24 hours

searchResults.AddRange(msc.GetHashList()); //List hashes from the past 24 hours

msc.Upload("<file path>") //Uploads a file to MalShare
