# API-Sniffer-Burp-Extension-
API Sniffer is a burp Suite Extension scanner to find exposed sensitive information (API keys - Weak Authentications - secret keys etc).

What is API-Sniffer?
The API Sniffer extension looks for API keys and credentials on websites that are in <b>scope only!</b>

The extension then add the information founded as an issue in the issues section in burp.
This is useful for doing web & mobile pentests and code reviews, because it helps identify keys that would otherwise either be missed or have to be searched for manually.

<h3>The current version (version 1.0) have 37 regexs to scan- more will be added in the future.</h3>


<h1>How to install:</h1> 
From the extender tab in burp >> go to extension tab >> press add >> then load the extension.
<br/>

<img width="600" alt="image2021-11-21_10-47-21" src="https://user-images.githubusercontent.com/46480509/142898129-34ff6828-6a7c-4130-bed7-c3d9ce7cadbd.png">

After that the extension should be loaded and a message should be printed out as shown below.
 
<img width="407" alt="image2021-11-21_10-50-35" src="https://user-images.githubusercontent.com/46480509/142898748-c9574543-4cd9-472b-ae4b-c9bd9bf30bd0.png">

<h1>How to use: </h1> 
* <b>The extension will scan only the URLs that is in scope. so make sure to add the targeted domain in scope. (we will test https://docs.hackerone.com/ as an example)</b><br />
* <b>The extension will not start scanning unless you start a passive scan.</b>



