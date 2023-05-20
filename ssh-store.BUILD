Apply this patch to OpenSSH 7.4p1 and build as normal.
This will make ssh-store as well as special versions of ssh-agent, scp, and sftp
(these scp and sftp don't disable agent forwarding and don't use the new
PermitLocalCommand option that is not supported by older versions of the ssh
client - useful if scp/sftp use the system default ssh).

On Linux, to make executables with static SSL libraries (libcrypto, in openssl-static rpm),
make with:

  LIBS="-Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lutil -lcrypt -lresolv -ldl -lz" ./configure

(or 'make LIBS=...') or whatever configure lists as libraries (last line of summary) with
-Wl,-Bstatic before the -lcrypto and -Wl,-Bdynamic after. Note that this only works for libcrypto
(the other libraries need to be compiled with -fPIC), but that's OK as it is the
only one that changes betweek CentOS7 and Alma9.

Add SSH_PROGRAM=ssh to get scp and sftp to use ssh from the PATH, rather than
the hard-coded /usr/local/bin/ssh.

The following are instructions for compiling with OpenSSH 5.2p1 with a previous version of this patch...

I built openssh-5.2p1-store-i386_linux24.tar.bz2 on yakut02 (Scientific Linux 3.0.9) with:

cd /usr/work/adye
wget http://hepunx.rl.ac.uk/~adye/software/ssh-store4.patch
wget -N ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-5.2p1.tar.gz
tar zxf openssh-5.2p1.tar.gz
cd openssh-5.2p1
patch -Zp1 < ../ssh-store4.patch
./configure
make install DESTDIR=/usr/work/adye/openssh-5.2p1-bin LIBS="-Wl,-Bstatic -lcrypto -lutil -lz -lnsl -lcrypt -lresolv -Wl,-Bdynamic" SSH_PROGRAM=ssh
cd /usr/work/adye/openssh-5.2p1-bin
find * \! -type d | tar cvjfT ../openssh-5.2p1-store-i386_linux24.tar.bz2 -

I built openssh-5.2p1-store-sun4x_510.tar.bz2 on tersk01 (SunOS 5.10) with:

wget http://hepunx.rl.ac.uk/~adye/software/ssh-store4.patch
wget -N ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-5.2p1.tar.gz
gunzip openssh-5.2p1.tar.gz
tar xf openssh-5.2p1.tar
cd openssh-5.2p1
patch -p1 < ../ssh-store4.patch
./configure
make install DESTDIR=/usr/work/adye/openssh-5.2p1-bin SSH_PROGRAM=ssh
cd /usr/work/adye/openssh-5.2p1-bin
tar cf ../openssh-5.2p1-store-sun4x_510.tar `find * \! -type d`
bzip2 ../openssh-5.2p1-store-sun4x_510.tar

