package Jira_OAuth;


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



=head1 NAME

OAuth - Perl OAuth API

=head1 SYNOPSIS

use OAuth;

Provides a perl module based API to register with an OAuth provider and make 
authenticated requests to it.

=head1 DESCRIPTION

This package provides a simple class based perl interface arround Net::OAuth 
to allow easy registration and to make authorised requests.

It is not particularilly feature complete but supplies the minimal 
functionality needed.

=head1 DEPENDENCIES

The following other perl packages are required:

=over

=item * LWP

=item * Crypt::OpenSSL::RSA

=item * URI

=item * HTTP::Request::Common

=item * Digest::SHA1

=item * Net::OAuth

=back

=head1 USAGE

Create a new instance with:

 my $oauth = OAuth->new(prot_version => "1.0a",
                        callback     => "<some url>");

Request access with:

 $oauth->request_request_token();
 
 my $authUrl = $oauth->generate_auth_request_url();
 print "Auth request URL: $authUrl\n";

Once the user has accepted the request in their web browser, then finish the 
process with:

 print "verifier: ";
 my $verifier = <STDIN>;
 chomp($verifier);

 $oauth->request_access_token($verifier);  

If you are using protocol version 1.0a then you need the verifier value sent to
your callback url, if your using 1.0 then you don't need the verifier value or 
the callback url. 

The class includes default values suitable for connecting to a Stash server on
localhost, you can however use it with any other 1.0/1.0a OAuth provider by 
supplying alternatives to the new command.

=head1 METHODS
=cut

use strict vars;

use Exporter;
use Carp;
use LWP;
use Crypt::OpenSSL::RSA;
use URI;
use CGI;
use HTTP::Request::Common ();
use MIME::Base64;
use Digest::SHA1 qw(sha1_hex);

use Net::OAuth;
require Net::OAuth::Request;
require Net::OAuth::RequestTokenRequest;
require Net::OAuth::AccessTokenRequest;
require Net::OAuth::ProtectedResourceRequest;

# Version
our $VERSION = '1.0';

# Export methods
our @ISA = qw(Exporter);

#==============================================================================#
# Constructor

=head2 new [param[s]]

Creates a new OAuth instance.

Takes hash style arguments, the following are supported

=over 12

=item prot_version

Protocol version.  Accepted values are "1.0" and "1.0a" (default: "1.0")
 
=item url

Base url for all requests (default: http://localhost:7990)

=item request_token_path

Relative url for token requests (default: /plugins/servlet/oauth/request-token)

=item authorize_token_path

Relative url for authorize requests (default: /plugins/servlet/oauth/authorize)

=item access_token_path

Relative url for access requests (default: /plugins/servlet/oauth/access-token)

=item consumer_key

The consumer key to connect with. (default: dpf43f3p2l4k3l03is)

=item auth_callback

(For 1.0a only) The callback to redirect to once the user has authorized a 
request.  This must display the verifier code in the URL to the user.

(The default is the same as the url, which is pretty meaningless so you need 
to pass a usefull value in when using 1.0a)

This value is ignored if prot_version is "1.0".

=item rsa_public_key_str

Public key string used by OAuth provider for this consumer (should include the 
begin end markers)

(default is the same as rsa.pub)

=item rsa_private_key_str

Private key string used to talk with OAuth provider for this consumer (should 
include the begin end markers)

(default is the same as rsa.pem)

=back

=cut

sub new {

    # Get class type
    my $proto = shift;
    my $class = ref($proto) || $proto;

    # Connect this and class
    my $this = {@_};
    bless $this, $class;

    # Initialise instance
    $this->_initialise();

    return $this;
}

#==============================================================================#
# Public Methods

=head2 resetTokens

Resets all current tokens (other than the consumer key), efectivly resetting 
the object back to the state it was in when constructed.

=cut

sub resetTokens {
    my $this = shift;

    for my $key
        (qw(request_token request_token_secret access_token access_token_secret))
    {
        delete $this->{$key};
    }
}

=head2 prot_version

Returns protocol version string ("1.0" or "1.0a").

When using 1.0 the verifier and callback are not used during authorisation dances.

=cut

sub prot_version {
    my $this = shift;

    return $this->{prot_version};
}

=head2 request_request_token

Requests a request token from the server.  Dies if it doesn't get one for any reason.

=cut

sub request_request_token {
    my $this    = shift;
    my %options = @_;

    # Perform request
    my $response = $this->_request( 'Net::OAuth::RequestTokenRequest',
        $this->_getUriFromKey("request_token_path"), 'POST' );

    # Check request result
    if ( !$response->is_success ) {
        croak "POST for "
            . $this->{request_token_path}
            . " failed: "
            . $response->status_line;
    }

    # Cast response into CGI query for easier parameter decoding
    my $response = new CGI( $response->content );

    # Save request token and secret
    $this->{request_token}        = $response->param('oauth_token');
    $this->{request_token_secret} = $response->param('oauth_token_secret');

    if ( $this->{prot_version} eq "1.0a" ) {
        my $callbackConfirmed = $response->param('oauth_callback_confirmed');
        if ( !$callbackConfirmed ) {
            croak "Callback was not confirmed in OAuth 1.0a response";
        }
    }
}

=head2 generate_auth_request_url [param[s]]

Assuming a valid request token has been recieved returns the url the user has 
to visit to authorize it.

Takes hash type parameters that are added to the resulting URL as key=value 
pairs with the normal encoding.

Returns a URI object.

=cut

sub generate_auth_request_url {
    my $this   = shift;
    my @extras = @_;

    if (   !exists $this->{request_token}
        || !exists $this->{request_token_secret} )
    {
        croak
            "Cannot request authorisation url when there is no pending authorisation";
    }

    # Get authroize url
    my $url = $this->_getUriFromKey("authorize_token_path");

 # Set its params to include oauth_token and anything extra passed to function
    my %params = (
        oauth_token => $this->{request_token},
        @extras
    );
    $url->query_form(%params);

    return $url;
}

=head2 request_access_token [param[s]]

Given a pending authorization request authorizes the request and gets the access tokens.

If using 1.0a the function takes the verifier code as the single argument

=cut

sub request_access_token {
    my $this     = shift;
    my $verifier = shift;

    # Check we have request tokens
    if (   !exists $this->{request_token}
        || !exists $this->{request_token_secret} )
    {
        croak
            "Cannot request access token when there is no pending authorisation";
    }

    # Check for verifier string
    if ( $this->{prot_version} eq "1.0a"
        && !$verifier )
    {
        croak "Cannot request access token without verifier string";
    }

    # Build params for query
    my $params = {
        token        => $this->{request_token},
        token_secret => $this->{request_token_secret}
    };

    if ( $this->{prot_version} eq "1.0a" ) {
        $params->{verifier} = $verifier;
    }
    my $content;
    # Perform request
    my $response = $this->_request(
        'Net::OAuth::AccessTokenRequest',
        $this->_getUriFromKey("access_token_path"),
        'POST', $content, params => $params
    );

    # Check request result
    if ( !$response->is_success ) {
        croak "POST for "
            . $this->{access_token_path}
            . " failed: "
            . $response->status_line;
    }

    # Cast response into CGI query for easier parameter decoding
    my $response = new CGI( $response->content );

    # Save access token and secret
    $this->{access_token}        = $response->param('oauth_token');
    $this->{access_token_secret} = $response->param('oauth_token_secret');

 # Now that we have a good access token/secret we dont need the request tokens
    for my $key (qw(request_token request_token_secret)) {
        delete $this->{$key};
    }
}

=head2 has_access_token

Returns 1/0 based on whether the instance has an access token

=cut

sub has_access_token {
    my $this = shift;

    # Check we have access tokens
    if (   !exists $this->{access_token}
        || !exists $this->{access_token_secret} )
    {
        return 0;
    }

    return 1;
}

=head2 get_access_token

Returns the current access token and secret (as a 2 element array)

=cut

sub get_access_token {
    my $this = shift;

    # Check we have access tokens
    if (   !exists $this->{access_token}
        || !exists $this->{access_token_secret} )
    {
        croak "Cannot retrieve access tokens when we don't have any";
    }

    return ( $this->{access_token}, $this->{access_token_secret} );
}

=head2 set_access_token [param[s]]

Sets the current access token and secret.

Takes the token and secret as its only arguments, in that order.

=cut

sub set_access_token {
    my $this                = shift;
    my $access_token        = shift;
    my $access_token_secret = shift;

    # Save access token and secret
    $this->{access_token}        = $access_token;
    $this->{access_token_secret} = $access_token_secret;

 # Now that we have a good access token/secret we dont need the request tokens
 # if they are kicking arround
    for my $key (qw(request_token request_token_secret)) {
        delete $this->{$key};
    }
}

=head2 get_access_token_crypt

Returns an encrypted string containing the current access token and secret.
This can be used to save the users granted access in a way that isn't 
human readable.

Uses the public/private key specified at startup (or the encoded defaults),
This isn't meant to be really secure, just not human readable.

=cut

sub get_access_token_crypt {
    my $this = shift;

    # Check we have access tokens
    if (   !exists $this->{access_token}
        || !exists $this->{access_token_secret} )
    {
        croak
            "Cannot generate crypt from instance without access token and secret";
    }

    my $toCrypt = $this->{access_token} . "\n" . $this->{access_token_secret};
    my $crypt
        = encode_base64( $this->{rsa_public_key}->encrypt($toCrypt), "" );

    return $crypt;
}

=head2 set_access_token_from_crypt [param[s]]

Assumes a string returned from get_access_token_crypt, decrypts it and uses
it to set the access token and secret

Uses the public/private key specified at startup (or the encoded defaults).

Takes the encrypted string as its only argument.

=cut

sub set_access_token_from_crypt {
    my $this    = shift;
    my $crypt   = shift;
    my %options = @_;

    my $deCrypt = $this->{rsa_private_key}->decrypt( decode_base64($crypt) );

    my ( $token, $secret ) = split( "\n", $deCrypt );
    if ( !$token || !$secret ) {
        if ( $options{nocroak} ) {
            return 0;
        }

        croak "Encrypted access details are not of valid format";
    }

    # Set keys as active
    $this->set_access_token( $token, $secret );

    return 1;
}



=head2 make_request [param[s]]

Makes a request to the server containing the access tokens.

This is the main method you will use once you've gone through the access token 
dance and gotten a token.

This method takes two fixed arguments:

=over 12

=item method

The method (GET, POST etc.) to use for the request.

=item sub-url

The url (under the base url) to send the request to

=back

Followed by two optional hash style arguments:

=over 12

=item params

A hash reference containing extra key:value pairs to be added to the request.  
For GET, PUT, POST they go in the final URL, for others they go in the request 
headers.

=item headers

A hash reference containing extra key:value pairs to be added to the request 
header.  Unlike the params hash these values never go in the URL.

If you are using a REST API this is where you should put the:

  Accepts => "application/json"
  
header value.

=back 

Returns a HTTP::Response.

For example:

 my $response = $oauth->make_request("GET",
                                     "rest/api/1.0/projects/CST/repos",
                                     params => {limit => 500, start => 0},
                                     headers => {Accepts => "application/json"});
  
=cut

sub make_request {
    my $this   = shift;
    my $method = shift;
    my $subUrl = shift;
    my $content = shift;
    my %extras = @_;

    if ( !$this->has_access_token() ) {
        croak "Cannot make oauth request without oauth access token";
    }

    # Perform request
    my $response = $this->_request(
        'Net::OAuth::ProtectedResourceRequest',
        $this->_getUriFromString($subUrl),
        $method,
        $content,
        params => {
            token        => $this->{access_token},
            token_secret => $this->{access_token_secret},
            extra_params => $extras{params}
        },
        headers => $extras{headers}
    );

    return $response;
}

#==============================================================================#
# Private Methods

# Sets default values for various parameters if set by user in the new call
sub _initialise {
    my $this    = shift;
    my %options = @_;

    # Set protocol version
    $this->{prot_version} ||= "1.0";    # Default to 1.0 version of protocol

    # Stash OAuth entry points
    $this->{url} ||= 'http://localhost:7990';
    $this->{request_token_path} ||= '/plugins/servlet/oauth/request-token',
        $this->{authorize_token_path} ||= '/plugins/servlet/oauth/authorize',
        $this->{access_token_path} ||= '/plugins/servlet/oauth/access-token',

        # Sanitise url (remove trailing slashes)
        $this->{url} =~ s/\/*$//;

    # Stash consumer details
    $this->{consumer_key};
    $this->{auth_callback} ||= $this->{url};

    # Set up RSA key strings and Crypt object for private key
    $this->{rsa_public_key_str};

    $this->{rsa_public_key}
        = Crypt::OpenSSL::RSA->new_public_key( $this->{rsa_public_key_str} );
    $this->{rsa_public_key}->use_pkcs1_padding();

    $this->{rsa_private_key_str};
    $this->{rsa_private_key} = Crypt::OpenSSL::RSA->new_private_key(
        $this->{rsa_private_key_str} );
    $this->{rsa_private_key}->use_pkcs1_padding();

    # Set up LibWWWPerl for HTTP requests
    $this->{user_agent} ||= LWP::UserAgent->new;
}

# Makes a URI out of the base url and an arbitrary key
sub _getUriFromKey {
    my $this = shift;
    my $key  = shift;

    # Get base url and make sure it ends in exactly one slash
    my $url = $this->{url};
    $url =~ s~/*$~/~;

    # Get second half and make sure it does not start with a slash
    my $rest = $this->{$key};
    $rest =~ s~^/+~~;

    # Combine two
    $url .= $rest;

    return URI->new($url);
}

sub _getUriFromString {
    my $this   = shift;
    my $subUrl = shift;

    # Get base url and make sure it ends in exactly one slash
    my $url = $this->{url};
    $url =~ s~/*$~/~;

    # Make sure second half does not start with a /
    $subUrl =~ s~^/+~~;

    # Combine two
    $url .= $subUrl;

    return URI->new($url);
}

# Formats and performs a request returning a HTTP::Response
sub _request {
    my $this   = shift;
    my $class  = shift;
    my $aUri   = shift;
    my $method = uc(shift);
    my $content = shift;
    my %extra  = @_;

# Make a local copy of the URI and extract an query params removing them from the URI
# We re-add the query params down in Net::OAuth so they are not lost
    my $uri   = URI->new($aUri);
    my %query = $uri->query_form;

    my $extra_params = { %{ $extra{params} } };    # Copy of hashref contents
    if ( $this->{prot_version} eq "1.0a" ) {
        $extra_params->{"callback"} = $this->{auth_callback};
    }

    my $request = $class->new(
        consumer_key    => $this->{consumer_key},
        consumer_secret => "ignored"
        ,    # RSA-SHA1 doesn't use this but the API needs it specified anyway
        request_url      => $uri,
        request_method   => $method,
        signature_method => 'RSA-SHA1',
        protocol_version => ( $this->{prot_version} eq "1.0a" )
        ? Net::OAuth::PROTOCOL_VERSION_1_0A
        : Net::OAuth::PROTOCOL_VERSION_1_0,
        timestamp     => time,
        nonce         => $this->_generate_nonce,
        signature_key => $this->{rsa_private_key},
        extra_params  => \%query,
        %{$extra_params}
    );

    # Sign the request
    $request->sign;

    # Check everything built fine
    if ( !$request->verify ) {
        croak "Unable to verify requent parameters";
    }

    # Build everything in to the final request
    my @headers = ();
    my $params = $request->to_hash;    # Get out all params from request as a hashref
    if (   'GET' eq $method
        || 'PUT' eq $method
        || 'POST' eq $method )
    {
        # Set all params into uri (key=value&key=value form in URL itself)

        my %newparms=(%$params,%query);
        $uri->query_form(%newparms);

        # Just put the fixed headers in headers
        my $headers = HTTP::Headers->new( %{ $extra{headers} } );
        @headers = ($headers);
    }
    else {
        # Move all params in to headers (nothing in URL)
        my $headers = HTTP::Headers->new( %$params, %{ $extra{headers} } );
        @headers = ($headers);
    }

    # Perform request
    my $req = HTTP::Request->new( $method , $uri, @headers, $content );

print STDERR "internal URI: $uri\n";

    my $response = $this->{user_agent}->request($req);

    return $response;
}

# generate a random nonce value
sub _generate_nonce {
    return int( rand( 2**32 ) );
}

#==============================================================================#
# All done
1;
