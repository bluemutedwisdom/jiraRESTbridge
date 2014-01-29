jiraRESTbridge
==============

JIRA REST API bridge


Requirements:

Optconfig
LWP
JSON
Crypt::OpenSSL::RSA
URI
CGI
HTTP::Request
MIME::Base64
Digest::SHA1
Net::OAuth

Install:

Apache2 config:
<Location /jiraRESTbridge/>
    Options +ExecCGI
</Location>
AddHandler cgi-script .cgi


Accessing Jira through the bridge:

-all URLs need to be prefixed with /jiraRESTbridge/jiraRESTbridge.cgi/
Example:    jira urL:   /rest/api/latest/issue/OPS-123 :   /jiraRESTbridge/jiraRESTbridge.cgi/rest/api/latest/issue/OPS-123

all requests need to either:
-include the 'jira_access_token' URL parameter (unless using a browser directly) in the URL (useful for curl or scripting)
-access the URL via a browser, which will redirect to get Oauth information as needed, storing the access token in an encrypted cookie

PUTs/POSTs/GETs all work against these URLs.