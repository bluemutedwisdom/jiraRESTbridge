#!/usr/bin/perl


   # Copyright 2014 Evernote Inc.

   # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at

   #     http://www.apache.org/licenses/LICENSE-2.0

   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.




use strict vars;
use lib '/usr/local/lib';
use JSON;
use Optconfig;
use Jira_OAuth;
use CGI;
use URI;
use URI::Escape;
use Log::Log4perl qw(:easy);


my ( $access_token_cookie, $oauth_token, $request_token_secret_cookie,
    $verifier_token, $callback_url );
my $proto="1.0a";

# initialize config
my $opt = Optconfig->new(
    'jiraRESTbridge',
    {   rsa_private_key => "UNCONFIGURED",
        rsa_public_key  => "UNCONFIGURED",
        consumer_key    => "1234234535464567",
        jira_url => "https://example.jira.com",
        request_token_path   => "/plugins/servlet/oauth/request-token",
        authorize_token_path => "/plugins/servlet/oauth/authorize",
        access_token_path    => "/plugins/servlet/oauth/access-token",
        logconfig => "/usr/local/etc/jirarestbridge_log4perl.conf",
        debug => 0
    }
);
my $DEBUG=$opt->{debug};
my $log_config_file=$opt->{'logconfig'};
Log::Log4perl::init($log_config_file);
my $logger = Log::Log4perl->get_logger('jirarestbridge');

# initialize CGI and request path
my $q            = new CGI;

$logger->debug("found body: " . $q->param('PUTDATA')) if $q->param('PUTDATA');
$q->{cookies_to_send}=[];
my $uri=URI->new($q->self_url);
my $target_path=$q->path_info;
my $parms=$q->Vars;
$target_path =~ s|^/||;
my @target_path = split('/',$target_path);

if($target_path[0] eq 'auth')
{
    if( $q->url_param('callback') )
    {
        $callback_url=$q->url_param('callback');
    }
    else
    {
        $proto="1.0";
        $callback_url = undef;
    }
    my $oauth=makeOauth($proto,$callback_url,$opt);
    my $authURL=initiateOauthRequest($oauth);
    print $q->header;
    print $authURL . "\n";
    my $verify_url=$q->self_url;
    $verify_url=~s/auth//;
    print $verify_url . "verify/" . $oauth->{request_token}  . "/" . $oauth->{request_token_secret} . "\n";
    exit;
}

# handle verifying an oauth request and returning the bare access token
if ( $target_path[0] eq 'verify' ) {
    my $oauth=makeOauth('1.0','',$opt);
    $oauth->{request_token}        = $target_path[1];
    $oauth->{request_token_secret} = $target_path[2];

    $oauth->request_access_token();
    print $q->header;
    print uri_escape($oauth->get_access_token_crypt()) . "\n";
    exit;
}


# we are trying to use the bridge to talk to Jira REST
if ( $target_path[0] eq 'rest' ) {

    # set callback url to this, in case we have to go get auth for this
    $callback_url= $uri->as_string;

    my $oauth=makeOauth($proto,$callback_url,$opt);

    # Attempt to load access token from cookie
    my $access_token = undef;
    if ( $q->cookie('jira_access_token') ) {
        $logger->debug("Access token found in cookie\n");
        $access_token = $q->cookie('jira_access_token');
        $oauth->set_access_token_from_crypt( $access_token, nocroak => 1 );
    }
    # OR handle request for access_token comming in on URL param
    if($q->url_param('jira_access_token'))
    {
        $logger->debug("Access token found in URL param");;
        $oauth->set_access_token_from_crypt( uri_unescape($q->url_param('jira_access_token')), nocroak => 1 );
    }


    # redirect to oauth auth if we don't have an oauth cookie and 
    # are not coming back from an authorization (would see verifier)
    &redirectToAuth($q,$oauth) if ( !$q->url_param('oauth_verifier') && !$oauth->has_access_token() );

    # else see if we're coming back from getting auth
    if (  !$oauth->has_access_token()
        && $q->url_param('oauth_verifier')
        && $q->url_param('oauth_token') )
    {
        $logger->debug("Verifier token found in URL");
        processOauthVerifier(
            $q,
            $oauth,
            $q->url_param('oauth_token'),
            $q->url_param('oauth_verifier')
        );
    }
    my $request = {
        path   => $target_path,
        method => $ENV{'REQUEST_METHOD'},
        body   => ($ENV{'REQUEST_METHOD'} ? $q->param($ENV{'REQUEST_METHOD'} . 'DATA'): '')
    };

    $logger->debug("sending body:" . $ENV{'REQUEST_METHOD'} . 'DATA' .  $q->param($ENV{'REQUEST_METHOD'} . 'DATA') );
    doHttpRequest( $q, $oauth, $request );
    exit;
}

print $q->header;
printDoc();
# END Processing of request



#########################

# handles callback from oauth auth and encrypts the token into a cookie saved in browser
# and redirect back to the original URL
sub processOauthVerifier {
    my $q = shift;
    my $oauth          = shift;
    my $oauth_token    = shift;
    my $oauth_verifier = shift;

    $oauth->{request_token} = $oauth_token;
    if ( $q->cookie('request_token_secret') ) {
        my $request_token_secret_cookie = $q->cookie(
            -name  => 'request_token_secret',
            -value => '',
            -expires=> '-1d'
        );
        $oauth->{request_token_secret}
            = $q->cookie('request_token_secret');
        push(@{$q->{cookies_to_send}}, $request_token_secret_cookie);
   }

# For 1.0a we need to ask for the verifier, for 1.0 just waiting until they verify is enough
    if ( $oauth->prot_version() eq "1.0a" ) {
        $oauth->request_access_token($oauth_verifier);
    }
    else {
        $oauth->request_access_token();
    }

    # Save access token into cookie
    $logger->debug("sending header with access_token_cookie");
    $access_token_cookie = $q->cookie(
        -name  => 'jira_access_token',
        -value => $oauth->get_access_token_crypt(),
        -expires => '+2y'
    );
    $logger->debug("Access token saved\n");

    my $uri=URI->new($q->self_url);
    my %parms=$uri->query_form;
    #remove the params that the oauth sends back
    delete $parms{oauth_token};
    delete $parms{oauth_verifier};

    $uri->query_form(\%parms,";");
    my $redirect_url=$uri->as_string;
    # now check to see if the original call contained a callback
    # if so, redirect back to that
    if($parms{'callback'})
    {
        $redirect_url = $parms{'callback'};

    }



    # then redirect back to the original URL that we were trying to hit
    print $q->redirect(
        -uri    => $redirect_url,
        -cookie => [$request_token_secret_cookie,$access_token_cookie]
    );
    $logger->debug("URI redirect after access_token: " . $uri->as_string);

    exit;
}

# constructs the http request and processes it. this request is oauth signed
sub doHttpRequest {
    my $cgi=shift;
    my $oauth=shift;
    my $request = shift;

    my $uri=URI->new($q->self_url);
    my %parms=$uri->query_form;

    delete $parms{'jira_access_token'};

    $uri->query_form(\%parms,";");

    my $url_to_fetch= $request->{path} . ( $uri->query ? "?" . $uri->query : "");

    $logger->debug("fetching $request->{method}: " . $oauth->_getUriFromString($url_to_fetch));

    my $response = $oauth->make_request(
        $request->{method},
        $url_to_fetch,
        $request->{body},
        headers => {
            -cookie=> $cgi->{cookies_to_send},
            Accepts        => "application/json",
            "Content-Type" => "application/json"
        }
    );
    print $cgi->header(-status=>$response->code);

    # If a success convert the results from JSON and dump them, otherwise show an error
    if ( $response->is_success ) {
        print $response->content;
        exit;
    }
    else {
        print "Request failed: " . $response->status_line . "\n";
    }
}

# create and return new oauth object
sub makeOauth {
    my $proto = shift;
    my $callback_url=shift;
    my $opt=shift;
    # Create new Jira_OAuth object
    my $oauth = Jira_OAuth->new(
        prot_version         => $proto,
        auth_callback        => $callback_url,
        url                  => $opt->{jira_url},
        request_token_path   => $opt->{request_token_path},
        authorize_token_path => $opt->{authorize_token_path},
        access_token_path    => $opt->{access_token_path},
        consumer_key         => $opt->{consumer_key},
        rsa_private_key_str  => $opt->{rsa_private_key},
        rsa_public_key_str   => $opt->{rsa_public_key}
    );    # Callback ignored if prot_version isn't "1.0a"
    return $oauth;
}

# initiatest the oauth request and returns the auth URL
sub initiateOauthRequest {
    my $oauth=shift;
    $logger->debug("Requesting request token");
    $oauth->request_request_token();

    return $oauth->generate_auth_request_url();
}

# generates and auth request and sends the request to the auth via location header
# the request URL is in the oauth request, as a callback, so after the user auths,
# the oauth provider will redirect back to the original URL but with verification tokens 
sub redirectToAuth {
    my $q=shift;
    my $oauth = shift;

    my $authUrl = initiateOauthRequest($oauth);
    my $request_token_secret_cookie = $q->cookie(
        -name  => 'request_token_secret',
        -value => $oauth->{request_token_secret}
    );

    print $q->header(
        -location    => $authUrl,
        -cookie => $request_token_secret_cookie
    );
    $logger->debug("Auth request URL: $authUrl");
    exit;
}

sub printDoc {
    print <<EOD
This is supposed to be help text....

EOD

}



