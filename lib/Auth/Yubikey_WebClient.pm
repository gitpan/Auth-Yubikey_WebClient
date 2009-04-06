package Auth::Yubikey_WebClient;

use warnings;
use strict;
use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use LWP::Simple;

=head1 NAME

Auth::Yubikey_WebClient - Authenticating the Yubikey against the Yubico Web API

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';

=head1 SYNOPSIS

Authenticate against the Yubico server via the Web API in Perl

Sample CGI script :-

	#!/usr/bin/perl

	use CGI;
	$cgi = new CGI;
	$otp = $cgi->param("otp");

	print "Content-type: text/html\n\n";
	print "<html>\n";
	print "<form method=get>Yubikey : <input type=text name=otp size=40 type=password></form>\n";

	use Auth::Yubikey_WebClient;

	$id = "<enter your id here>";
	$api = "<enter your API key here>";

	if($otp)
	{
        	$result = Auth::Yubikey_WebClient::yubikey_webclient($otp,$id,$api);
		# result can be either ERR or OK

        	print "Authentication result : <b>$result</b><br>";
	}

	print "</html>\n";


=head1 FUNCTIONS

=head2 yubikey_webclient

=cut

sub yubikey_webclient
{
	my ($otp,$id,$api) = @_;

	my $response = get("http://api.yubico.com/wsapi/verify?id=$id&otp=$otp");
	chomp($response);
	if($response !~ /status=ok/i)
	{
		# If the status is not ok, let's not even go through the rest...
		$response =~ m/status=(.+)/;
		return "ERR_$1";
	}

	#extract each of the lines, and store in a hash...

	my %result;	
	foreach (split(/\n/,$response))
	{
		chomp;
                if($_ =~ /=/)
                {
                        ($a,$b) = split(/=/,$_,2);
                        $b =~ s/\s//g;
                        $result{$a} = $b;
                }
        }

        # save the h parameter, that's what we'll be comparing to

        my $signatur=$result{h};
        delete $result{h};
        my $datastring='';

	my $key;
        foreach $key (sort keys %result)
        {
                $result{$key} =~ s/\s//g;
                $datastring .= "$key=$result{$key}&";
        }
        $datastring = substr($datastring,0,length($datastring)-1);

        my $hmac = encode_base64(hmac_sha1($datastring,decode_base64($api)));

        chomp($hmac);

        if($hmac eq $signatur)
        {
                return "OK";
        }
        else
        {
                return "ERR_HMAC";
        }
}

=head1 USAGE

Before you can use this module, you need to register for an API key at Yubico.  This is as simple as logging onto <https://api.yubico.com/yms/getapi.php> and entering your Yubikey's OTP and a brief description.  Once you have the API and ID, you need to provide those details to the module to work.

=head1 AUTHOR

Phil Massyn, C<< <phil at massyn.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-auth-yubikey_webclient at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Auth-Yubikey_WebClient>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Auth::Yubikey_WebClient


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Auth-Yubikey_WebClient>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Auth-Yubikey_WebClient>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Auth-Yubikey_WebClient>

=item * Search CPAN

L<http://search.cpan.org/dist/Auth-Yubikey_WebClient>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2009 Phil Massyn, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1; # End of Auth::Yubikey_WebClient
