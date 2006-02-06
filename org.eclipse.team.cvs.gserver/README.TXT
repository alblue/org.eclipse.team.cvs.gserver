This contains an initial implementation of the GServer protocol for Eclipse. It uses the built-in GSSAPI support for 
Java 1.4 in order to authenticate against a CVS server that has been set up with GSSAPI support. GSSAPI is a plugin
that allows any kind of authentication to be made against any kind of server; however, this plugin has been coded
to expect Kerberos V5 to be used.

It has been tested so far on Mac OS X 10.4, but required some configuration and changes on the server before it would work.

It has several known issues at this point, and should not be considered production ready.

IMPORTANT NOTE: This does NOT do any encryption of the data between client and server. It merely leverages the existing 
setup in order to use the kerberos credentials without needing any further authentication. (That's not to say it's not
possible; it just hasn't been done in the version you're reading this from.)

Requirements
------------
Eclipse 3.1 (this is not tested against 3.2, though I hope to provide a version for that soon)
Java 1.4+
Kerberos KDCv5 already set up with authenticating kerberos clients
(this will not work with KerberosV4)
NB The kerberos server must support one of des-cbc-md5, des-cbc-crc and des3-cbc-sha1

Instructions for use
--------------------

Download the org.eclipse.team.cvs.gserver fragment from the attachment at https://bugs.eclipse.org/bugs/show_bug.cgi?id=41097
and copy it into the plugins/ directory to install it. (I'm not setting up an update server until it works, by hopefully
by then if it does, it can make it into the 3.2 stream)

Read from the sections below:

o Setting up the server
o Setting up the client
o Setting up Eclipse


Setting up the server
---------------------

The CVS server expects to use a kerberos principal of 'cvs/fqdn.example.com'. You will need to generate this key in your kerberos server
before you will be able to do anything. You also need to add that to the kerberos keytab and make it available for the CVS server to read.
If you are running the CVS server under a different group/user, then you might want to export a specific keytab just to hold the CVS credentials
and then start up the CVS server with KRB5_KTNAME=/path/to/cvs.keytab -- but this is dependent on your kerberised CVS and kerberos server.
Since I haven't tried this, I'd appreciate any info with whether it's been successfully done and on what systems.

If you have a kerberized CVS currently running PServer connections, you don't need to do anything else.

To run a server, run the 'cvs server' command from inetd, by adding the following line:

cvspserver stream tcp nowait cvs /usr/bin/cvs cvs --allow-root=/path/to/cvsroot server

(the cvspserver should be the name for port 2401 in your /etc/services file; if not, replace it with the one that is here
and of course update the directory for your CVS root.)

Setting up the client
---------------------

If all is well, you should be able to do the following:

o Run kinit to get your TGT
o Run klist to verify a ticket exists; if it says 'No Kerberos 5 tickets in credential cache' then it hasn't worked.
o cvs -d :gserver:fqdn.example.com/path/to/cvsroot checkout SomeProject

This should authenticate with the kerberos server and checkout a project that exists already. If you don't get this
working, then it's almost certain that the Eclipse one won't work. Common causes for failure:
o The host name must be exact. Even if fqdn.example.org and fqdn.example.com resolve to the same machine, it won't work.
o The IP address must be exact. If fqdn.example.com is an alias for fqdn1.example.com and fqdn2.example.com, it won't work.
o Are the times (roughly) the same? The norm is to allow them to be apart for < 5 minutes. Any greater, and it won't work.
o Is there a credential for cvs/fqdn.example.com added to your kerberos server? Run ktadmin.local (or whatever) to find out.
On MIT Kerberos, the commands to add a principal are:
(sudo) ktadmin.local
add_principal -randkey cvs/fqdn.example.com <- this generates the principal
ktadd cvs/fqdn.example.com <- this exports it to the keytab

Don't forget to kinit first. The CVS client doesn't prompt you for a userid/password; you have to do it prior to running cvs.

Setting up Eclipse
------------------

If your :gserver: CVS server is running, then you should be able to try and set up Eclipse.

Run kinit to obtain an initial TGT token (this plugin doesn't yet obtain this for you regardless of user/password settings)
Start up Eclipse
Create a new CVS repostory as follows:
Host fqdn.example.com
CVSRoot /path/to/cvsroot
Port 2401 (not tested on others, but should work; can leave blank as default)
Connection type: gserver

User: you need to put something in this box to finish, but it's ignored (at present)
Password: it's ignored (at present)

If you have 'validate connection on finish' it should try to make a connection to the server.
It may take a few seconds (up to 10) to authenticate, but if it's hanging any longer than that,
it probably has hung (see known issues below).

Known issues
------------

Login hangs without valid kerberos ticket

  If you don't run kinit first, the kerberos server asks for the userid/password from the console. It can appear to hang
  if you don't notice it (and you're running from a javaw or similar that doesn't have a console). The only solution
  is death at that point, so you don't want to do it without (a) saving your work, and (b) testing this first. I'm working
  on getting it to use the credentials you supply when you make the connection, but for the meantime, the way to do it
  is to ensure that kinit is run first before starting the connection. It should be possible to run kinit from a different
  shell whilst Eclipse is running, but you need to do it before you kick off any operation that will cause the CVS server
  to kick in.

javax.security.auth.login.LoginException: KrbException: KDC has no support for encryption type (14) - KDC has no support for encryption type
  The KDC must support one of des-cbc-md5, des-cbc-crc and des3-cbc-sha1 in order to work. You will have to re-export the key to the keytab
  after changing the key encryption types (ktadd on MIT kerberos ktadmin.local)
  (on Mac OS X 10.4 Server, I had to add des-cbc-crc to the /var/db/krbkdc/kdc.conf supported_enctypes and kdc_supported_enctypes fields)
  http://java.sun.com/j2se/1.5.0/docs/guide/security/jgss/tutorials/Troubleshooting.html

  Also
  Cause 2: This exception is thrown when using native ticket cache on some Windows platforms. Microsoft has added a new feature in which they no longer export the session keys for Ticket-Granting Tickets (TGTs). As a result, the native TGT obtained on Windows has an "empty" session key and null EType. The effected platforms include: Windows Server 2003, Windows 2000 Server Service Pack 4 (SP4) and Windows XP SP2.

  Solution 2: You need to update the Windows registry to disable this new feature. The registry key allowtgtsessionkey should be added--and set correctly--to allow session keys to be sent in the Kerberos Ticket-Granting Ticket.

  On the Windows Server 2003 and Windows 2000 SP4, here is the required registry setting:

  HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters
  Value Name: allowtgtsessionkey
  Value Type: REG_DWORD
  Value: 0x01  ( default is 0 )
  By default, the value is 0; setting it to "0x01" allows a session key to be included in the TGT.
  Here is the location of the registry setting on Windows XP SP2:

  HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\
  Value Name: allowtgtsessionkey
  Value Type: REG_DWORD
  Value: 0x01
  


Alex Blewitt
Alex.Blewitt@gmail.com