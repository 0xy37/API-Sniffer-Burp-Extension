# API-Sniffer-Burp-Extension-
API Sniffer is a burp Suite Extension scanner to find exposed sensitive information (API keys - Weak Authentications - secret keys etc).

The API Sniffer extension looks for API keys and credentials on websites that are in scope only! 
The extension then add the information founded as an issue in the issues section in burp.

This is useful for doing web pentests and code reviews, because it helps identify keys that would otherwise either be missed or have to be searched for manually.
The current version (version 1.0) have 37 regexs to scan- more will be added in the future.

<b>How to install:</b> 
