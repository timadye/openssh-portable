Apply this patch to OpenSSH 9.5p1 and build as normal.
This will make ssh-store as well as special versions of ssh-agent, scp, and sftp
(these scp and sftp don't disable agent forwarding and don't use the new
PermitLocalCommand option that is not supported by older versions of the ssh
client - useful if scp/sftp use the system default ssh).

Add make SSH_PROGRAM=ssh to get scp and sftp to use ssh from the PATH,
rather than the hard-coded /usr/local/bin/ssh.

Alma9 build from openssh-portable git repo
==========================================

  git clone https://github.com/openssh/openssh-portable.git
  cd openssh-portable
  git checkout V_8_7_P1
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/ssh-store7-alma9.patch
  patch -p1 < ssh-store7-alma9.patch
  sudo dnf install openssl-devel zlib-devel pam-devel
  autoreconf
  ./configure
  make -j4

Alma9 (and RHEL9) doesn't provide statically linked OpenSSL libraries, as CentOS7 did.

Alma9 build from source rpm
===========================

  sudo dnf groupinstall "Development Tools"
  sudo dnf install rpm-build rpmdevtools dnf-plugins-core
  sudo dnf config-manager --set-enabled crb  # Enable the CRB (CodeReady Builder) repository, which gives us libfido2-devel
  sudo dnf download --source openssh
  sudo dnf builddep openssh

  rpmdev-setuptree
  rpm -ivh openssh-8.7p1-47.el9_7.alma.1.src.rpm
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/ssh-store7-alma9-rpm.patch
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/openssh-8.7p1-47.el9_7.alma.1-store7.spec.patch
  cp ssh-store7-alma9-rpm.patch ~/rpmbuild/SOURCES/
  (cd; patch -p0) < openssh-8.7p1-47.el9_7.alma.1-store7.spec.patch

  rpmbuild -ba ~/rpmbuild/SPECS/openssh.spec

CentOS7 build
=============

  yum install openssl-static
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/ssh-store6-c7.patch
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/openssh-7.4p1-6-x86_64-centos7-store.spec.patch
  cp ssh-store6-c7.patch SOURCES/
  patch < openssh-7.4p1-6-x86_64-centos7-store.spec.patch
  rpmbuild -ba --define "static_openssl 1" SPECS/openssh.spec

This builds with static SSL libraries, which should help ssh work with later OS versions (eg. Alma9).

Other Linux
===========

  LIBS="-Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lutil -lcrypt -lresolv -ldl -lz" ./configure
  make install DESTDIR=$PWD/bin

This makes executables with static SSL libraries (libcrypto, in openssl-static rpm).
Can also use 'make LIBS=...' or whatever configure lists as libraries (last line of summary) with
-Wl,-Bstatic before the -lcrypto and -Wl,-Bdynamic after. Note that this only works for libcrypto
(the other libraries need to be compiled with -fPIC), but that's OK as it is the
only one that changes between CentOS7 and Alma9.

Cygwin build
============

1. Use setup.exe to install openssh src files and build pre-requisites (requires Administrator mode, unless -B is used):
  /setup-x86_64.exe -q -P cygport,autoconf,automake,gcc-g++,make,libcrypt-devel,libedit-devel,libfido2-devel,libkrb5-devel,libssl-devel,zlib-devel
  /setup-x86_64.exe -q -I -P openssh
2.
  cd /usr/src/openssh-10.2p1-1.src
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/cygwin/ssh-store7-cygwin.patch
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/cygwin/openssh-10.2p1-1-x86_64-store7.cygport.patch
  patch < openssh-10.2p1-1-x86_64-store7.cygport.patch
  mkdir patches
  mv ssh-store7-cygwin.patch patches/
  cygport openssh.cygport all

Windows build
=============

The Windows ssh-agent sources are in contrib/win32/win32compat/ssh-agent.
Keys and variables are stored in HKEY_CURRENT_USER\Software\OpenSSH, so they are
persistent and specific for each user connecting with ssh-add/ssh-store.

1.
  git clone https://github.com/PowerShell/openssh-portable.git
  cd openssh-portable
  git checkout v9.5.0.0
  wget --no-check-certificate https://hepunx.rl.ac.uk/~adye/software/ssh-store7-win32.patch
  patch -p1 < ssh-store7-win32.patch
2. Start Visual Studio 2022
3. Open contrib\win32\openssh\Win32-OpenSSH.sln
4. Switch to Release build
5. Build Solution
6. install in a user directory:
  cd bin\x64\Release
  mkdir C:\Apps\OpenSSH
  copy *.exe C:\Apps\OpenSSH
  copy *.txt C:\Apps\OpenSSH
7. configure custom ssh-agent service from an Administrator Command Prompt:
  sc create ssh-agent-store binPath= "C:\Apps\OpenSSH\ssh-agent.exe" DisplayName= "OpenSSH Authentication Agent store"
  sc description ssh-agent-store "Agent to hold private keys used for public key authentication. This version also supports ssh-store."
  sc config ssh-agent-store start= auto
  sc start ssh-agent-store
8. To use Windows ssh-agent from Cygwin or WSL: install socat and https://github.com/albertony/npiperelay . Start with:
  export SSH_AUTH_SOCK=/tmp/ssh-agent.$UID.sock
  umask 077
  setsid socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent",nofork &

==============================================================================

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

==============================================================================
