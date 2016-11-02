#!/usr/bin/perl -wl
use Digest::Perl::MD5 'md5_hex';
use POSIX qw(strftime);

$|=1;
my $password = 'blesswoyo';
my $errurl = 'http://err.woyo.com/woyo.mp3';
my $result = 'http://err.woyo.com/woyo.wma';

while (<>) {
        ($uri,$client,$ident,$method) = ( );
        ($uri,$client,$ident,$method) = split;
	my $time_from = strftime "%Y%m%d%H%M%S", localtime(time - 1*3600);
	my $time_to = strftime "%Y%m%d%H%M%S", localtime(time + 1*3600);
        next unless ($uri =~m/^http:\/\/(.+?)\/(.*)\?key=([0-9]{14})(.+)$/);
        if (($4 eq md5_hex("/".$2.$3.$password)) && ($3 > $time_from) && ($3 < $time_to)) {
                $result = "http:\/\/$1:81\/$2";
        } else {
                $result = $errurl;
        }
} continue {
        print $result;
}
