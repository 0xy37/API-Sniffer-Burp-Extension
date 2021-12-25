# API-Sniffer-Burp-Extension
API Sniffer is a burp Suite Extension scanner to find exposed sensitive information.
What is API-Sniffer?
The API Sniffer extension looks for API keys and credentials on websites that are in <b>scope only!</b>

The extension then add the information founded as an issue in the issues section in burp.
This is useful for doing web & mobile pentests and code reviews, because it helps identify keys that would otherwise either be missed or have to be searched for manually.

<h1>What does the extension capture:</h1> 

<table>
  <tr>
    <th>Google API Key</th>
    <th>Slack Token</th>
    <th>AWS API Key</th>
  </tr>
  <tr>
   <th>Slack Webhook</th>
    <th>Facebook Access Token	</th>
    <th>Facebook OAuth</th>
  </tr>
    <tr>
   <th>Mailgun API Key</th>
    <th>Twilio API key</th>
    <th>Paypal Access Token</th>
  </tr>
      <tr>
   <th>Square Oauth Secret</th>
    <th>Square Access Token</th>
    <th>Stripe Standard API</th>
  </tr>
   <tr>
   <th>Stripe Restricted</th>
    <th>API	Github keys</th>
    <th>RSA Private Key	</th>
  </tr>
     <tr>
   <th>SSH (EC) private key</th>
    <th>PGP Private Block</th>
    <th>Generic API Key</th>
  </tr>
  <tr>
   <th>Generic Secret</th>
    <th>Saudi National ID</th>
  </tr>
</table>



<h1>How to install:</h1> 
From the extender tab in burp >> go to extension tab >> press add >> then load the extension.
<br/>

<img width="600" alt="image2021-11-21_10-47-21" src="https://user-images.githubusercontent.com/46480509/142898129-34ff6828-6a7c-4130-bed7-c3d9ce7cadbd.png">

After that the extension should be loaded and a message should be printed out as shown below.
 
<img width="500" alt="image2021-11-21_10-50-35" src="https://user-images.githubusercontent.com/46480509/142898748-c9574543-4cd9-472b-ae4b-c9bd9bf30bd0.png">

<h1>How to use: </h1> 
* <b>The extension will scan only the URLs that is in scope. so make sure to add the targeted domain in scope.</b><br/>
* <b>The extension will not start scanning unless you start a passive scan.</b><br/>
* <b>The issues might take time to appear in the issues section, you can always check the extensions logs to see if the scanner catches anything.</b>
<img width="600" alt="image2021-11-21_11-8-58 (2)" src="https://user-images.githubusercontent.com/46480509/142899914-09dbc388-a8f1-4cc7-955f-49b34ee82cb3.png">
*<b>After a while you will start seeing potential issues added to burp</b>
<img width="500" alt="image2021-11-21_11-10-12" src="https://user-images.githubusercontent.com/46480509/142900057-48fb2669-c0b3-416b-abcd-175074e93c0e.png">
<img width="500" alt="image2021-11-21_11-10-44" src="https://user-images.githubusercontent.com/46480509/142900042-9b38c775-60b7-4d9a-aabf-8ae8279e5c26.png">


<h1>False positives Alert:</h1>
Yup you guessed it, you might have to interfere with False positives results. there is always room for improvements. 



<h1>How to exploit API keys</h1>

Each API key will be exploited differently, depending on the API found.</br>
Below is a great and a very comprehensive reference for how to exploit different API keys.</br>

https://github.com/streaak/keyhacks
