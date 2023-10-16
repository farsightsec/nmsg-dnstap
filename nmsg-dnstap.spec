Name:           nmsg-dnstap
Version:        0.1.0
Release:        1%{?dist}
Summary:        NMSG DNSTAP Tool

License:        MPLv2.0
URL:            https://github.com/farsightsec/nmsg-dnstap
Source0:        https://dl.farsightsecurity.com/dist/%{name}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  fstrm-devel
BuildRequires:  fstrm-utils
BuildRequires:  libevent-devel
BuildRequires:  libnmsg-devel
BuildRequires:  nmsgtool
BuildRequires:  zeromq-devel

%description

%package devel
Summary:        NMSG DNSTAP Tool
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Forward Frame Streams DNSTAP data in NMSG format to UDP or ZeroMQ endpoints, unfiltered.

%prep
%setup -q

%build
[ -x configure ] || autoreconf -fvi
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%files
%{_bindir}/*
%_mandir/man1/*

%doc

%changelog
