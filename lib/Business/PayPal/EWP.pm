package Business::PayPal::EWP;

use 5.006001;
use strict;
use warnings;
use Net::SSLeay;

require Exporter;
our %EXPORT_TAGS = ( 'all' => [ qw(SignAndEncrypt) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION='0.01';
require XSLoader;
XSLoader::load('Business::PayPal::EWP', $VERSION);

sub SignAndEncrypt {
    my $formdata=shift;
    my $key=shift;
    my $cert=shift;
    my $ppcert=shift;
    my $retval=1;
    my ($bio,$RSA,$ppX509,$X509,$pKey,$p7,$memBio,$p7Bio)=(undef,undef,undef,undef,undef,undef,undef,undef);
    Net::SSLeay::ERR_load_crypto_strings();
    Business::PayPal::EWP::OpenSSL_add_all_algorithms();
    # Load PayPal cert
    $bio=Net::SSLeay::BIO_new_file($ppcert,"rt");
    unless ($bio) {
	warn "Error loading file: ".$ppcert;
	$retval=0;
	goto END;
    }
    $ppX509=Business::PayPal::EWP::PEM_read_bio_X509($bio,0,0,0);
    unless ($ppX509) {
	warn "Error reading PayPal certificate from $ppcert";
	$retval=0;
	goto END;
    }
    Net::SSLeay::BIO_free($bio);
    # Load our public key
    $bio=Net::SSLeay::BIO_new_file($cert,"rt");
    unless ($bio) {
	warn "Error loading file: ".$cert;
	$retval=0;
	goto END;
    }
    $X509=Business::PayPal::EWP::PEM_read_bio_X509($bio,0,0,0);
    unless ($X509) {
	warn "Error reading certificate from $cert";
	$retval=0;
	goto END;
    }
    Net::SSLeay::BIO_free($bio);
    # Load our private key
    $bio=Net::SSLeay::BIO_new_file($key,"rt");
    unless ($bio) {
	warn "Error loading file: ".$key;
	$retval=0;
	goto END;
    }
    $RSA=Business::PayPal::EWP::PEM_read_bio_RSAPrivateKey($bio,0,0,0);
    unless ($RSA) {
	warn "Error reading RSA key from $key";
	$retval=0;
	goto END;
    }
    Net::SSLeay::BIO_free($bio);
    # Reformat
    $formdata=~s/,/\n/g;
    # Encrypt and sign
    $retval=Business::PayPal::EWP::sign_and_encrypt($formdata,$RSA,$X509,$ppX509,0);

END:
    if ($bio) {
	Business::PayPal::EWP::BIO_free_all($bio);
    }
    if ($ppX509) {
	Net::SSLeay::X509_free($ppX509);
    }
    if ($X509) {
	Net::SSLeay::X509_free($X509);
    }
    if ($RSA) {
	Net::SSLeay::RSA_free($RSA);
    }
    return $retval;
}

1;

__END__

=head1 NAME

Business::PayPal::EWP - Perl extension for PayPal's Encrypted Website Payments

=head1 SYNOPSIS

  use Business::PayPal::EWP qw(SignAndEncrypt);
  ...
  my $form="cmd=_xclick,business=...";
  my $cert="/path/to/mycert.crt";
  my $key="/path/to/mycert.key";
  my $ppcert="/path/to/paypalcert.pem";

  my $encrypted=SignAndEncrypt($form,$key,$cert,$ppcert);

  print <<EOF;

  <form action="https://www.paypal.com/cgi-bin/webscr" method="post">
  <input type="hidden" name="cmd" value="_s-xclick" />
  <input type="image" src="https://www.paypal.com/en_US/i/btn/x-click-but23.gif"
  border="0" name="submit" alt="Make payments with PayPal - it's fast, free and
  secure!" /><input type="hidden" name="encrypted" value="$encrypted" /></form>

  EOF

=head1 DESCRIPTION

This module wraps the sample C++/C# code which PayPal provides for working with
Encrypted Web Payments.  It contains a single function, SignAndEncrypt which takes
the plaintext form code, private key file, public key file, and PayPal's public
certificate, and will return the signed and encrypted code needed by paypal.

=head1 AUTHOR AND COPYRIGHT

Copyright (c) 2004, 2005 Issac Goldstand E<lt>margol@beamartyr.netE<gt> - All rights reserved.

This library includes code copied from L<Net::SSLeay> and PayPal's sample code.  More information
about those projects' authors can be found at the respective project websites.

This library is free software. It can be redistributed and/or modified
under the same terms as Perl itself.

=head1 SEE ALSO

L<Net::SSLeay>, L<CGI>, L<Business::PayPal>
Also, see PayPal's documentation at http://www.paypal.com/cgi-bin/webscr?cmd=p/xcl/rec/ewp-intro-outside

=cut


