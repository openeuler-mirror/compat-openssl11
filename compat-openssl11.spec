%define soversion 1.1
Name:        compat-openssl11
Version:     1.1.1m
Release:     4
Epoch:       1
Summary:     Cryptography and SSL/TLS Toolkit
License:     OpenSSL and SSLeay
URL:         https://www.openssl.org/
Source0:     https://www.openssl.org/source/openssl-%{version}.tar.gz
Source1:     Makefile.certificate
Patch1:      openssl-1.1.1-build.patch
Patch2:      openssl-1.1.1-fips.patch
Patch3:      CVE-2022-0778-Add-a-negative-testcase-for-BN_mod_sqrt.patch
Patch4:      CVE-2022-0778-Fix-possible-infinite-loop-in-BN_mod_sqrt.patch
Patch5:      CVE-2022-1292.patch
Patch6:      Backport-Support-raw-input-data-in-apps-pkeyutl.patch
Patch7:      Backport-Fix-no-ec-no-sm2-and-no-sm3.patch
Patch8:      Backport-Support-SM2-certificate-verification.patch
Patch9:      Backport-Guard-some-SM2-functions-with-OPENSSL_NO_SM2.patch
Patch10:     Backport-Add-test-cases-for-SM2-cert-verification.patch
Patch11:     Backport-Add-documents-for-SM2-cert-verification.patch
Patch12:     Backport-Fix-a-memleak-in-apps-verify.patch
Patch13:     Backport-Skip-the-correct-number-of-tests-if-SM2-is-disabled.patch
Patch14:     Backport-Make-X509_set_sm2_id-consistent-with-other-setters.patch
Patch15:     Backport-Support-SM2-certificate-signing.patch
Patch16:     Backport-Support-parsing-of-SM2-ID-in-hexdecimal.patch
Patch17:     Backport-Fix-a-double-free-issue-when-signing-SM2-cert.patch
Patch18:     Backport-Fix-a-document-description-in-apps-req.patch
Patch19:     Backport-Update-expired-SCT-certificates.patch
Patch20:     Backport-ct_test.c-Update-the-epoch-time.patch
Patch21:     Feature-Support-TLCP-protocol.patch
Patch22:     Feature-X509-command-supports-SM2-certificate-signing-with-default-sm2id.patch
Patch23:     CVE-2022-2068-Fix-file-operations-in-c_rehash.patch
Patch24:     CVE-2022-2097-Fix-AES-OCB-encrypt-decrypt-for-x86-AES-NI.patch
Patch25:     Feature-add-ARMv8-implementations-of-SM4-in-ECB-and-XTS.patch
Patch26:     Fix-reported-performance-degradation-on-aarch64.patch 
Patch27:     Feature-PKCS7-sign-and-verify-support-SM2-algorithm.patch
Patch28:     Backport-SM3-acceleration-with-SM3-hardware-instruction-on-aa.patch
Patch29:     Backport-SM4-optimization-for-ARM-by-HW-instruction.patch
Patch30:     Feature-SM4-XTS-optimization-for-ARM-by-HW-instruction.patch
Patch31:     backport-Fix-failure-to-check-result-of-bn_rshift_fixed_top.patch
Patch32:     backport-Test-processing-of-a-duplicated-HRR.patch
Patch33:     backport-tls_process_server_hello-Disallow-repeated-HRR.patch
Patch34:     backport-Avoid-potential-memory-leak.patch
Patch35:     backport-Fix-NULL-pointer-dereference-for-BN_mod_exp2_mont.patch
Patch36:     backport-crypto-x509-v3_utl.c-Add-missing-check-for-OPENSSL_s.patch
Patch37:     backport-Fix-password_callback-to-handle-short-passwords.patch
Patch38:     backport-Fix-usage-of-SSLfatal.patch
Patch39:     backport-Fix-integer-overflow-in-evp_EncryptDecryptUpdate.patch
Patch40:     backport-Fix-Coverity-1201763-uninitialised-pointer-read.patch
Patch41:     backport-Fix-Coverity-1498611-1498608-uninitialised-read.patch
Patch42:     backport-Fix-coverity-1498607-uninitialised-value.patch
Patch43:     backport-Check-password-length-only-when-verify-is-enabled.patch
Patch44:     backport-Fix-issue-where-OBJ_nid2obj-doesn-t-always-raise-an-.patch
Patch45:     backport-Set-protocol-in-init_client.patch
Patch46:     backport-Fix-a-crash-in-ssl_security_cert_chain.patch
Patch47:     backport-Fix-undefined-behaviour-in-EC_GROUP_new_from_ecparam.patch
Patch48:     backport-Fix-a-memory-leak-in-ec_key_simple_oct2priv.patch
Patch49:     backport-Fix-a-crash-in-asn1_item_embed_new.patch
Patch50:     backport-Fix-leakage-when-the-cacheline-is-32-bytes-in-CBC_MA.patch
Patch51:     backport-Add-test-for-empty-supported-groups-extension.patch
Patch52:     backport-Do-not-send-an-empty-supported-groups-extension.patch
Patch53:     backport-x509-use-actual-issuer-name-if-a-CA-is-used.patch
Patch54:     backport-ticket_lifetime_hint-may-exceed-1-week-in-TLSv1.3.patch
Patch55:     backport-Fix-a-memory-leak-in-crl_set_issuers.patch
Patch56:     backport-Fix-a-DTLS-server-hangup-due-to-TLS13_AD_MISSING_EXT.patch
Patch57:     backport-Fix-an-assertion-in-the-DTLS-server-code.patch
Patch58:     backport-Fix-a-memory-leak-in-X509_issuer_and_serial_hash.patch
Patch59:     backport-Fix-strict-client-chain-check-with-TLS-1.3.patch
Patch60:     backport-Fix-a-crash-in-X509v3_asid_subset.patch
Patch61:     backport-Fix-a-memory-leak-in-EC_GROUP_new_from_ecparameters.patch
Patch62:     backport-Fix-range_should_be_prefix-to-actually-return-the-co.patch
Patch63:     backport-v3_sxnet-add-a-check-for-the-return-of-i2s_ASN1_INTE.patch
Patch64:     backport-Fix-bn_gcd-code-to-check-return-value-when-calling-B.patch
Patch65:     backport-Add-missing-header-for-memcmp.patch
Patch66:     backport-Fix-a-memory-leak-in-tls13_generate_secret.patch
Patch67:     backport-Make-the-DRBG-seed-propagation-thread-safe.patch
Patch68:     backport-Fix-memory-leak-in-X509V3_add1_i2d-when-flag-is-X509.patch
Patch69:     fix-add-loongarch64-target.patch
Patch70:     backport-APPS-x509-With-CA-but-both-CAserial-and-CAcreateseri.patch 
Patch71:     backport-Fix-verify_callback-in-the-openssl-s_client-s_server.patch 
Patch72:     backport-Fix-re-signing-certificates-with-different-key-sizes.patch 
Patch73:     backport-Fix-ipv4_from_asc-behavior-on-invalid-Ip-addresses.patch 
Patch74:     backport-Test-case-for-a2i_IPADDRESS.patch 
Patch75:     backport-Fix-test-case-for-a2i_IPADDRESS.patch 
Patch76:     backport-Fix-a-crash-in-v2i_IPAddrBlocks.patch 
Patch77:     backport-Fixes-segfault-occurrence-in-PEM_write.patch 
Patch78:     backport-X509_REQ_get_extensions-Return-empty-stack-if-no-ext.patch 
Patch79:     backport-Fix-EC_KEY_set_private_key-priv_key-regression.patch 
Patch80:     backport-Add-test-for-EC_KEY_set_private_key.patch 
Patch81:     backport-Fix-SSL_pending-and-SSL_has_pending-with-DTLS.patch 
Patch82:     backport-Test-that-swapping-the-first-app-data-record-with-Fi.patch
Patch83:     backport-Always-end-BN_mod_exp_mont_consttime-with-normal-Mon.patch
Patch84:     backport-Add-an-extra-reduction-step-to-RSAZ-mod_exp-implemen.patch
Patch85:     backport-Coverity-1508534-1508540-misuses-of-time_t.patch
Patch86:     backport-Moving-notify-check-after-the-no-time-check.patch
Patch87:     backport-Convert-serverinfo-in-SSL_CTX_use_serverinfo-to-v2.patch
Patch88:     backport-X509-x509_req.c-Set-modified-flag-when-X509_req_info.patch
Patch89:     backport-ssl_cipher_process_rulestr-don-t-read-outside-rule_s.patch
Patch90:     backport-CVE-2022-4304-Fix-Timing-Oracle-in-RSA-decryption.patch
Patch91:     backport-CVE-2022-4450-Avoid-dangling-ptrs-in-header-and-data-params-for-PE.patch
Patch92:     backport-CVE-2023-0215-Check-CMS-failure-during-BIO-setup-with-stream-is-ha.patch
Patch93:     backport-CVE-2023-0215-Fix-a-UAF-resulting-from-a-bug-in-BIO_new_NDEF.patch
Patch94:     backport-CVE-2023-0286-Fix-GENERAL_NAME_cmp-for-x400Address-1.patch

BuildRequires: gcc perl make lksctp-tools-devel coreutils util-linux zlib-devel

%description
OpenSSL is a robust, commercial-grade, and full-featured toolkit for the
Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols.

%package libs
Summary:      A general purpose cryptography library with TLS implementation
Group:        System Environment/Libraries
Requires:     ca-certificates >= 2008-5
Requires:     crypto-policies >= 20180730
Conflicts:    openssl-libs < 1:3.0

%description libs
The openssl-libs package contains the libraries that are used
by various applications which support cryptographic algorithms
and protocols.


%package devel
Summary:   Development files for openssl
Requires:  %{name}-libs%{?_isa} = %{epoch}:%{version}-%{release}
Requires: krb5-devel zlib-devel pkgconfig
Conflicts: openssl-devel
%description devel
%{summary}.

%prep
%autosetup -n openssl-%{version} -p1

%build

sslarch=%{_os}-%{_target_cpu}
%ifarch x86_64 aarch64
sslflags=enable-ec_nistp_64_gcc_128
%endif
%ifarch loongarch64
sslflags="--libdir=%{_libdir}"
%endif

RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -DPURIFY $RPM_LD_FLAGS"
./Configure \
    --prefix=%{_prefix} \
    --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
    zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
    enable-cms enable-md2 enable-rc5 enable-ssl3 enable-ssl3-method \
    enable-weak-ssl-ciphers \
    no-mdc2 no-ec2m enable-sm2 enable-sm3 enable-sm4 enable-tlcp \
    shared ${sslarch} $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\""'

%make_build all

%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    crypto/fips/fips_standalone_hmac $RPM_BUILD_ROOT%{_libdir}/libcrypto.so.%{version} >$RPM_BUILD_ROOT%{_libdir}/.libcrypto.so.%{version}.hmac \
    ln -sf .libcrypto.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libcrypto.so.%{soversion}.hmac \
    crypto/fips/fips_standalone_hmac $RPM_BUILD_ROOT%{_libdir}/libssl.so.%{version} >$RPM_BUILD_ROOT%{_libdir}/.libssl.so.%{version}.hmac \
    ln -sf .libssl.so.%{version}.hmac $RPM_BUILD_ROOT%{_libdir}/.libssl.so.%{soversion}.hmac \
%{nil}

%install

%make_install

# rename so name with actual version
rename so.%{soversion} so.%{version} $RPM_BUILD_ROOT%{_libdir}/*.so.%{soversion}
# create symbolic link
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{version} ; do
     ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`
     ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`.%{soversion}
done

# Next step of gradual disablement of ssl3.
# Make SSL3 disappear to newly built dependencies.
sed -i '/^\#ifndef OPENSSL_NO_SSL_TRACE/i\
#ifndef OPENSSL_NO_SSL3\
# define OPENSSL_NO_SSL3\
#endif' $RPM_BUILD_ROOT/%{_prefix}/include/openssl/opensslconf.h

# Delete configuration files
rm -rf  $RPM_BUILD_ROOT/%{_sysconfdir}/pki/tls/*

# Delete man pages 
rm -rf $RPM_BUILD_ROOT/%{_mandir}/*
rm -rf $RPM_BUILD_ROOT/%{_datadir}/doc

# Remove binaries
rm -rf $RPM_BUILD_ROOT/%{_bindir}

%check
LD_LIBRARY_PATH=`pwd`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
export LD_LIBRARY_PATH
crypto/fips/fips_standalone_hmac libcrypto.so.%{soversion} >.libcrypto.so.%{soversion}.hmac
ln -s .libcrypto.so.%{soversion}.hmac .libcrypto.so.hmac
crypto/fips/fips_standalone_hmac libssl.so.%{soversion} >.libssl.so.%{soversion}.hmac
ln -s .libssl.so.%{soversion}.hmac .libssl.so.hmac
OPENSSL_ENABLE_MD5_VERIFY=
export OPENSSL_ENABLE_MD5_VERIFY
OPENSSL_SYSTEM_CIPHERS_OVERRIDE=xyz_nonexistent_file
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE
make test || :

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig


%files libs
%defattr(-,root,root)
%license LICENSE
%{_libdir}/libcrypto.so.%{version}
%{_libdir}/libcrypto.so.%{soversion}
%{_libdir}/libssl.so.%{version}
%{_libdir}/libssl.so.%{soversion}
%{_libdir}/engines-%{soversion}
%attr(0644,root,root) %{_libdir}/.libcrypto.so.*.hmac
%attr(0644,root,root) %{_libdir}/.libssl.so.*.hmac

%files devel
%defattr(-,root,root)
%doc doc/dir-locals.example.el doc/openssl-c-indent.el
%{_prefix}/include/openssl
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so
%{_libdir}/*.a


%ldconfig_scriptlets libs

%changelog
* Wed Mar 08 2023 fangxiuning <fangxiuning@huawei.com> - 1:1.1.1m-4
- Fix some cves

* Tue Mar 07 2023 fangxiuning <fangxiuning@huawei.com> - 1:1.1.1m-3
- Fix some cves

* Thu Jan 19 2023 licihua <licihua@huawei.com> - 1:1.1.1m-2
- Add Conflicts for compat-openssl11-devel compat-openssl11-lib

* Fri Jan 13 2023 licihua <licihua@huawei.com> - 1:1.1.1m-1
- Repackge openssl-1.1.1m into compat-openssl11
