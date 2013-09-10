# sslnuke -- SSL without verification isn't secure!
--------------------------------------

We have all heard over and over that SSL without verification is not secure. 
If an SSL connection is not verified with a cached certificate, it can easily be
hijacked by any attacker. So in 2013, one would think we had totally done away with this
problem. Browsers cache certificates and very loudly warn the user when a site has
offered up a self-verified certificate and should not be trusted, browser vendors have
pretty much solved this problem. However, HTTPS is not the only protocol that uses
SSL. Unfortunately, many clients for these other protocols do not verify by default and even
if they did, there is no guarantee of secure certificate transfer. After all, how many 
people are willing to pay $50 for an SSL certificate for their FTPS server? 

A common protocol that uses SSL but is rarely verified is IRC. Many IRC clients
verify by default, but most users will turn this off because IRC servers administrators
tend not to purchase legitimate SSL certificates. Some popular clients even leave
SSL verification off by default (IRSSI, for example). We already know that this is 
unwise, any attacker between a user and the IRC server can offer an invalid
certificate and decrypt all of the user's traffic (including possibly sensitive
messages). Most users don't even consider this fact when connecting to an
SSL "secured" IRC server. 

The purpose of sslnuke is to write a tool geared towards decrypting and intercepting
"secured" IRC traffic. There are plenty of existing tools that intercept SSL traffic already,
but most of these are geared towards HTTP traffic. sslnuke targets IRC directly in order to 
demonstrate how easy it is to intercept "secured" communications. sslnuke usage is simple.

## Usage

First, add a user account for sslnuke to run as and add iptables rules to redirect traffic
to it:

    # useradd -s /bin/bash -m sslnuke
    # grep sslnuke /etc/passwd
    sslnuke:x:1000:1000::/home/sslnuke:/bin/bash
    # iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner 1000 -m tcp \
      --dport 6697 --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 4444

Finally, login as sslnuke, build, and run sslnuke:

    # su -l sslnuke
    # cd sslnuke
    # make
    # ./sslnuke

Run an IRC client and login to your favorite IRC network using SSL,
IRC messages will be printed to stdout on sslnuke.

    [*] Received connection from: 192.168.0.5:58007
    [*] Opening connection to: 1.1.1.1:6697
    [*] Connection Using SSL!
    [*] irc.com -> AUTH (1.1.1.1): *** Looking up your hostname...
    [*] irc.com -> AUTH (1.1.1.1): *** Found your hostname
    [*] irc.com -> victim (1.1.1.1): *** You are connected to irc.vps-heaven.com with TLSv1.2-AES256-GCM-SHA384-256bits
    [*] 192.168.0.5 -> nickserv (192.168.0.5): id hello
    [*] NickServ!services@irc.com -> victim (1.1.1.1): Password accepted - you are now recognized.

sslnuke will automatically detect a client using SSL and determine whether or not
to use SSL. The code could also be easily modified to show web site passwords or
FTP data, anything using SSL. To attack users on a network, sslnuke can be used
in conjunction with an ARP poisoning tool, such as the one found at [Blackhat Library](http://www.blackhatlibrary.net/Python#Scapy)
or it can be deployed on a gateway.

A video demonstration of sslnuke can be seen at [ascii.io](http://ascii.io/a/5370).

## Mitigation

Now on to the important part, how do we verify SSL connections? The first step is to
transfer the SSL certificate over an alternative medium, the best way would be to
have the administrator directly give you the certificate. However, if this is not possible,
openssl can download the certificate from the server:

    # openssl s_client -showcerts -connect irc.com:6697 </dev/null

Save the certificate into ~/.irssi/ssl/irc.com.crt. It is best to run the command from a 
computer on a different network than yours to prevent this from being intercepted. Next, to
configure IRSSI to use the certificate, save a network:

    /network add irc
    /server add -ssl_cafile ~/.irssi/ssl/irc.com.crt -network irc -port 6697 irc.com

If IRSSI ever gets an invalid certificate, it will warn you and disconnect immediately. However,
for the truly paranoid, a Tor hidden service or VPN should be used. To configure automatic
Tor hidden service redirection on Linux one can run the following commands:

    # echo "VirtualAddrNetwork 10.192.0.0/10" >> /etc/tor/torrc
    # echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
    # echo "TransPort 9040" >> /etc/tor/torrc
    # echo "DNSPort 5353" >> /etc/tor/torrc
    # killall -HUP tor
    # iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040
    # iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
    # ncat xxxxxxxxxxxxxxx.onion 6667
    :irc.com NOTICE AUTH :*** Looking up your hostname...
    :irc.com NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
    ^C

Ultimately, IRC clients should use an SSH-style key verification. On first connect, present the
certificate fingerprint to the user and force the user to confirm it and then cache the certificate.
If it changes the next time, do not allow the connection.

## Source

The source code can be downloaded on [Github](https://github.com/jtripper/sslnuke).

## Credit

* jtripper -- jack@jtripper.net
* [Blackhat Library](http://blackhatlibrary.net/)
* [Chokepoint](http://chokepoint.net)

