Summary:   PAM Module to authenticate against an IMAP server
Name:      pam-imap
Version:   0.3.9
Release:   1
URL:       https://sourceforge.net/projects/pam-imap/
Source:    https://github.com/wdoekes/pam-imap/releases/download/v%{version}/%{name}_%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License:   GPL
Group:     Applications/System

BuildRequires: pam-devel

Obsoletes: pam_imap

%description
This is a PAM module that authenticates a user login against a remote 
IMAP or IMAPS server.  The module supports a server rollover, so a 
list of servers can be successively queried if the previous server is 
down. With a bit of PAM configuration hacking, it will also work with 
other modules to allow logins to be authenticated locally and / or 
remotely with IMAP on the same system. 


%prep
%setup -q

%build
%configure
%{__make} 

%install
%{__rm} -rf %{buildroot}
%{__install} -d %{buildroot}/lib/security
%{__install} -d %{buildroot}%{_sbindir}
%{__install} -d %{buildroot}/etc/pam.d/
%{__make} install DESTDIR=%{buildroot}
%{__install} -m 755 check_user %{buildroot}%{_sbindir}
%{__install} -m 644 conf/check_user %{buildroot}/etc/pam.d/
%{__install} -m 644 conf/imap-auth %{buildroot}/etc/pam.d/
%{__install} -m 644 conf/pam_imap.conf %{buildroot}/etc/pam.d/

%clean
%{__rm} -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc BUGS CHANGES COPYING CREDITS README TODO conf/login.example conf/smtp.example
/lib/security/*
%{_sbindir}/*
%config(noreplace) /etc/pam.d/*

%changelog
* Fri Jan 16 2009 Richard C. Greenwood <rcgreenw@slotechs.com>
- Created spec file
