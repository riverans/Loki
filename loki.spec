Name:           loki
Version:        0.2.7
Release:        1%{?dist}
Summary:        loki

License:        BSD
URL:            http://codecafe.de
Source0:        http://codecafe.de/loki/loki-0.2.7.tar.gz

BuildRequires:  automake autoconf python-devel libpcap-devel libdnet-devel openssl-devel
Requires:       python pylibpcap libdnet-python python-IPy python-dpkt pygtk2 openssl pygtk2-libglade

%description


%prep
%setup -q
aclocal
autoconf
automake --add-missing --copy
sed -i "s/+ e/+ str(e)/g" setup.py.in

%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%doc
%{python_sitearch}/*
/usr/bin/loki.py
/usr/bin/mpls_tunnel
/usr/share/loki/*



%changelog
