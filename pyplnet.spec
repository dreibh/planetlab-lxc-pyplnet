%define name pyplnet
%define version 7.0
%define taglevel 0

%define release %{taglevel}%{?pldistro:.%{pldistro}}%{?date:.%{date}}

Summary: PlanetLab Network Configuration library
Name: %{name}
Version: %{version}
Release: %{release}
License: PlanetLab
Group: System Environment/Daemons
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Vendor: PlanetLab
Packager: PlanetLab Central <support@planet-lab.org>
Distribution: PlanetLab %{plrelease}
URL: %{SCMURL}

Requires: python3
BuildRequires: python3, python3-devel
BuildArch: noarch

%description
pyplnet is used to write the network configuration files based on the
configuration data recorded at PLC.

%prep
%setup -q

%build
python3 setup.py build

%install
rm -rf $RPM_BUILD_ROOT
python3 setup.py install --skip-build --root "$RPM_BUILD_ROOT"
chmod +x $RPM_BUILD_ROOT/%{python3_sitelib}/plnet.py
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
ln -s %{python3_sitelib}/plnet.py $RPM_BUILD_ROOT/%{_bindir}/plnet

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/plnet
%{python3_sitelib}/*

%changelog
* Mon Jan 07 2019 Thierry Parmentelat <thierry.parmentelat@inria.fr> - pyplnet-7.0-0
- based on python3
- remove 'NM_CONTROLLED=no' from ifcfg file, as we now rely on NetworkManager
- cleaned up old code related to 'nodenetworks', oly use 'interfaces' instead

* Sun Jul 10 2016 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-19
- always set NM_CONTROLLED=no in ifcfg files
- more modern python

* Fri Aug 09 2013 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-18
- IPv6 changes from Thomas Dreibholz

* Fri Aug 09 2013 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-17
- Added tags for configuring OvS interfaces

* Thu Jan 03 2013 Scott Baker <smbaker@gmail.com> - pyplnet-4.3-16
- verify ovs is running before setting up ovs bridge

* Wed Oct 24 2012 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-15
- Add support for bridging using Open vSwitch

* Wed May 02 2012 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-14
- Fix stupid bug

* Mon Apr 30 2012 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-13
- Support for VLAN interfaces

* Thu Apr 26 2012 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-12

* Sun Sep 25 2011 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-11
- turn off verbose/debug messages
- pyplnet-4.3-10 was broken because of that

* Wed Sep 21 2011 Andy Bavier <acb@cs.princeton.edu> - pyplnet-4.3-10
- Enable creation of bridged interfaces

* Tue Feb 15 2011 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-9
- protect shell vars definition in ifcfg files with ""
- tweaks in numbering rules

* Mon Jan 24 2011 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-8
- no semantic change - just fixed specfile for git URL

* Thu Dec 09 2010 Daniel Hokka Zakrisson <dhokka@cs.princeton.edu> - pyplnet-4.3-7
- Secondary interface fixes and features.

* Wed Apr 28 2010 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-6
- aliases don't show up in /sys, so use /sbin/ip to get the configured IP addresses instead

* Thu Feb 11 2010 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-5
- This is needed for 5.0, as GetSlivers now exposes 'interfaces' and no 'networks' anymore
- this code can handle both..

* Tue Sep 29 2009 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-4
- alias without a mac address: fix runtime error while issuing warning

* Tue Jun 09 2009 Stephen Soltesz <soltesz@cs.princeton.edu> - pyplnet-4.3-3
- this patch addresses mlab and other multi-interface node confgurations where
- the generated boot image and network config files are mis-named.

* Wed Apr 22 2009 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-2
- handle wireless settings back again

* Fri Apr 17 2009 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - pyplnet-4.3-1
- fixes for 4.3

* Tue Dec  2 2008 Daniel Hokka Zakrisson <daniel@hozac.com> - pyplnet-4.3-1
- initial release
