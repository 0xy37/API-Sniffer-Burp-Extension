# API Sniffer Scanner: Burp Suite Extension to find exposed sensitive information (API keys - Weak Authentications - secret keys).
# Author : Yara AlHumaidan (0xY37)
# https://github.com/0xy37/API-Sniffer-Burp-Extension


# Code Credits:
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks


# Regex Credits:
# https://github.com/trufflesecurity/Trufflehog-Chrome-Extension

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re

############################################################################


version = 1.0 # update this whenever we add more regex to the exten


# Implement BurpExtender to inherit from multiple base classes
# IBurpExtender is the base class required for all extensions
# IScannerCheck lets us register our extension with Burp as a custom scanner check
class BurpExtender(IBurpExtender, IScannerCheck):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("API Sniffer")
        self._callbacks.registerScannerCheck(self)
        
        print """
		
API Sniffer
                                                                            
        """ 
        print "Burp APISniffer loaded successfully"
        print "Current version is:"
        print version
   
        
        return

    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0


############################################################################


    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = []
        tmp_issues = []

        # Create an instance of our CustomScans object, passing the
        # base request and response, and our callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        # Call the findRegEx method of our CustomScans object to check
        # the response for anything matching a specified regular expression
        
        
        # Artifactory API Token
        regex = "(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}"
        issuename = "API Sniffer has Sniffed: Artifactory API Token"
        issuelevel = "Information"
        issuedetail = """Artifactory API Token: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                          Also consider searching further for threats of the found API."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Google API Key
        regex = "AIza[0-9A-Za-z-\\_]{35}"
        issuename = "API Sniffer has Sniffed: Google API Key"
        issuelevel = "Information"
        issuedetail = """Google API Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                          Also consider searching further for threats of the found API."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
  
  
        # Authorization Basic
        regex = "basic [a-zA-Z0-9_\\-:\\.=]+"
        issuename = "API Sniffer has Sniffed: Authorization Basic"
        issuelevel = "High"
        issuedetail = """Authorization Basic: <b>$asset$</b>
                         <br><br><b>Note:</b> The HTTP Basic Authentication scheme is not considered to be a secure method of user authentication (unless used in conjunction with some external secure system such as TLS/SSL), as the user name and password are passed over the network as cleartext."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
 
        # Authorization Bearer
        regex = "bearer [a-zA-Z0-9_\\-\\.=]+"
        issuename = "API Sniffer has Sniffed: Authorization Bearer"
        issuelevel = "Information"
        issuedetail = """Authorization Bearer: <b>$asset$</b>
                         <br><br><b>Note:</b> Bearer authentication (also called token authentication) is an HTTP authentication scheme that involves security tokens called bearer tokens. Also consider searching further for threats regarding the used authentication method."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
 
  
        # AWS API Key
        regex = "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"
        issuename = "API Sniffer has Sniffed: AWS API Key"
        issuelevel = "Information"
        issuedetail = """AWS API Key: <b>$asset$</b>
                         <br><br><b>Note:</b>  Please note that a manual review is recommended as some of these issues could be false positives.
                          Also consider searching further for threats of the found API. 
                          Reference: https://docs.aws.amazon.com/cli/latest/reference/s3api/list-buckets.html"""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Docs Files Exetension
        regex = "^.*\.(xls|xlsx|doc|docx)$"
        issuename = "API Sniffer has Sniffed: Docs Files Exetension"
        issuelevel = "Information"
        issuedetail = """Docs Files Exetension: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                          Also consider running exiftool against the discovered files and look any useful information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Slack API Key
        regex = "xox.-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"
        issuename = "API Sniffer has Sniffed: Slack API Key"
        issuelevel = "Information"
        issuedetail = """Slack API Key: <b>$asset$</b>
                         <br><br><b>Note:</b>  Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found API."""

        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Basic Auth Credentials
        regex = "(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+"
        issuename = "API Sniffer has Sniffed: Basic Auth Credentials"
        issuelevel = "Information"
        issuedetail = """Basic Auth Credentials: <b>$asset$</b>
                         <br><br><b>Note:</b>Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Google Cloud Platform Auth
        regex = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        issuename = "API Sniffer has Sniffed: Google Cloud Platform Auth"
        issuelevel = "Information"
        issuedetail = """Google Cloud Platform Auth: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Google Cloud Platform API
        regex = "[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}"
        issuename = "API Sniffer has Sniffed: Google Cloud Platform API"
        issuelevel = "Information"
        issuedetail = """Google Cloud Platform API: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Firebase
        regex = "AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
        issuename = "API Sniffer has Sniffed: Firebase"
        issuelevel = "Information"
        issuedetail = """Firebase: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Google Oauth
        regex = "ya29\.[0-9A-Za-z\-_]+"
        issuename = "API Sniffer has Sniffed: Google Oauth"
        issuelevel = "Information"
        issuedetail = """Google Oauth: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Amazon AWS Access key ID 
        regex = "A[SK]IA[0-9A-Z]{16}"
        issuename = "API Sniffer has Sniffed: Amazon AWS Access key ID"
        issuelevel = "Low"
        issuedetail = """Amazon AWS Access key ID: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Amazon MWS Auth Token
        regex = "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        issuename = "API Sniffer has Sniffed: Amazon MWS Auth Token"
        issuelevel = "Low"
        issuedetail = """Amazon MWS Auth Token: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Amazon AWS url
        regex = "s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com"
        issuename = "API Sniffer has Sniffed: Amazon AWS url"
        issuelevel = "Information"
        issuedetail = """Amazon AWS url: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information.
                         Reference: https://docs.aws.amazon.com/cli/latest/reference/s3api/list-buckets.html"""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Authorization API
        regex = "api[key|\s*]+[a-zA-Z0-9_\-]+"
        issuename = "API Sniffer has Sniffed: Authorization API"
        issuelevel = "Information"
        issuedetail = """Authorization API: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


        # Mailgun API Key
        regex = "key-[0-9a-zA-Z]{32}"
        issuename = "API Sniffer has Sniffed: Mailgun API Key"
        issuelevel = "Information"
        issuedetail = """Mailgun API Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
      
        
	# Twilio API key
        regex = "SK[0-9a-fA-F]{32}"
        issuename = "API Sniffer has Sniffed: Twilio API key"
        issuelevel = "Information"
        issuedetail = """Twilio API key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


	# Paypal Braintree Access Token
        regex = "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
        issuename = "API Sniffer has Sniffed: Paypal Braintree Access Token"
        issuelevel = "Information"
        issuedetail = """Paypal Braintree Access Token: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


	# Square Oauth Secret
        regex = "sq0csp-[0-9A-Za-z\\-_]{43}"
        issuename = "API Sniffer has Sniffed: Square Oauth Secret"
        issuelevel = "Information"
        issuedetail = """Square Oauth Secret: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


	# Square Access Token
        regex = "sq0atp-[0-9A-Za-z\\-_]{22}"
        issuename = "API Sniffer has Sniffed: Square Access Token"
        issuelevel = "Information"
        issuedetail = """Square Access Token: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
 
 
	# Stripe Standard API
        regex = "sk_live_[0-9a-zA-Z]{24}"
        issuename = "API Sniffer has Sniffed: Stripe Standard API"
        issuelevel = "Information"
        issuedetail = """Stripe Standard API: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
  
  
	# Stripe Restricted API
        regex = "rk_live_[0-9a-zA-Z]{24}"
        issuename = "API Sniffer has Sniffed: Stripe Restricted API"
        issuelevel = "Information"
        issuedetail = """Stripe Restricted API: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []


	# Github
        regex = "[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]"
        issuename = "API Sniffer has Sniffed: Github"
        issuelevel = "Low"
        issuedetail = """Github: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
 
 
 	# RSA Private Key
        regex = "-----BEGIN RSA PRIVATE KEY-----"
        issuename = "API Sniffer has Sniffed: RSA Private Key"
        issuelevel = "Critical"
        issuedetail = """RSA Private Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
     
                
 	# SSH DSA Private Key
        regex = "-----BEGIN DSA PRIVATE KEY-----"
        issuename = "API Sniffer has Sniffed: SSH DSA Private Key"
        issuelevel = "Critical"
        issuedetail = """SSH DSA Private Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []
 
 
  	# SSH EC Private key
        regex = "-----BEGIN EC PRIVATE KEY-----"
        issuename = "API Sniffer has Sniffed: SSH DC Private key"
        issuelevel = "Critical"
        issuedetail = """SSH DC Private key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
 
 
  	# PGP Private Block
        regex = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        issuename = "API Sniffer has Sniffed: PGP Private Block"
        issuelevel = "Critical"
        issuedetail = """PGP Private Block: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               


  	# Artifactory Password
        regex = "(?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}"
        issuename = "API Sniffer has Sniffed: Artifactory Password"
        issuelevel = "Information"
        issuedetail = """Artifactory Password: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
        

  	# Google Drive Oauth
        regex = "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
        issuename = "API Sniffer has Sniffed: Google Drive Oauth"
        issuelevel = "Information"
        issuedetail = """Google Drive Oauth: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
 
 
   	# LinkedIn Secret Key
        regex = "(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]"
        issuename = "API Sniffer has Sniffed: LinkedIn Secret Key"
        issuelevel = "Information"
        issuedetail = """LinkedIn Secret Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
 
 

    	# Twitter Oauth
        regex = "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
        issuename = "API Sniffer has Sniffed: Twitter Oauth"
        issuelevel = "Information"
        issuedetail = """Twitter Oauth: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               


    	# Twitter Secret Key
        regex = "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}"
        issuename = "API Sniffer has Sniffed: Twitter Secret Key"
        issuelevel = "Information"
        issuedetail = """Twitter Secret Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
                
                
     	# Generic API Key
        regex = "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]"
        issuename = "API Sniffer has Sniffed: Generic API Key"
        issuelevel = "Information"
        issuedetail = """Generic API Key: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
                
                
      	# Generic Secret
        regex = "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]"
        issuename = "API Sniffer has Sniffed: Generic Secret"
        issuelevel = "Information"
        issuedetail = """Generic Secret: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
 
 
       	# Saudi Phone number
        regex = "((\+966)|966|05)[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]|[0-9]"
        issuename = "API Sniffer has Sniffed: Saudi Phone number"
        issuelevel = "Information"
        issuedetail = """Saudi Phone number: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               


       	# JSON Web Token
        regex = "eyJhbGciOiJ"
        issuename = "API Sniffer has Sniffed: JSON Web Token"
        issuelevel = "Information"
        issuedetail = """JSON Web Token: <b>$asset$</b>
                         <br><br><b>Note:</b> Please note that a manual review is recommended as some of these issues could be false positives.
                         Also consider searching further for threats of the found information."""
        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)
        scan_issues = scan_issues + tmp_issues
        tmp_issues = []               
        
        
        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None
                    
                
############################################################################



class CustomScans:
    def __init__(self, requestResponse, callbacks):
        # Set class variables with the arguments passed to the constructor
        self._requestResponse = requestResponse
        self._callbacks = callbacks

        # Get an instance of IHelpers, which has lots of useful methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()

        # Put the parameters from the HTTP message in a class variable so we have class-level scope
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
        return


    # This is a custom scan method to Look for all occurrences in the response
    # that match the passed regular expression
    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        # Only check responses for 'in scope' URLs

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            
            # Compile the regular expression, telling Python to ignore EOL/LF
            myre = re.compile(regex, re.DOTALL)


            # Using the regular expression, find all occurrences in the base response
            match_vals = myre.findall(self._helpers.bytesToString(response))

            for ref in match_vals:
                #url = self._helpers.analyzeRequest(self._requestResponse).getUrl()

                # For each matched value found, find its start position, so that we can create
                # the offset needed to apply appropriate markers in the resulting Scanner issue
                offsets = []
                start = self._helpers.indexOf(response, str(ref), True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)


                # Create a ScanIssue object and append it to our list of issues, marking
                # the matched value in the response.

                if (issuename == "API Sniffer has Sniffed: Artifactory API Token"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Google API Key"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Authorization Basic"):
                    try:
                        print "Authorization Basic found: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Authorization Bearer"):
                    try:
                        print "Authorization Bearer found: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: AWS API Key"):
                    try:
                        print "AWS Client ID: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Docs Files Exetension"):
                    try:
                        print "Files found: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Slack API Key"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Basic Auth Credentials"):
                    try:
                        print "Basic Auth Credentials found: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Google Cloud Platform Auth"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Google Cloud Platform API"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Firebase"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Google Oauth"):
                    try:
                        print "Oauth: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Amazon AWS Access key ID"):
                    try:
                        print "Key ID: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Amazon MWS Auth Token"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Amazon AWS url"):
                    try:
                        print "URL: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Authorization API"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Mailgun API Key"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Twilio API key"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Paypal Braintree Access Token"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Square Oauth Secret"):
                    try:
                        print "Secret: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Square Access Token"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Stripe Standard API"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Stripe Restricted API"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Github"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: RSA Private Key"):
                    try:
                        print "Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: SSH DSA Private Key"):
                    try:
                        print "Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: SSH DC Private key"):
                    try:
                        print "Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: PGP Private Block"):
                    try:
                        print "Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Artifactory API Token"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Artifactory Password"):
                    try:
                        print "Password: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Google Drive Oauth"):
                    try:
                        print "Oauth: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: LinkedIn Secret Key"):
                    try:
                        print "Secret Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Twitter Oauth"):
                    try:
                        print "Oauth: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Twitter Secret Key"):
                    try:
                        print "Secret Key: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Generic API Key"):
                    try:
                        print "API: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Generic Secret"):
                    try:
                        print "Secret: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: Saudi Phone number"):
                    try:
                        print "Phone number: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                elif (issuename == "API Sniffer has Sniffed: JSON Web Token"):
                    try:
                        print "Token: "+ref
                        scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                    except:
                        continue
                      
        return (scan_issues)

############################################################################

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
