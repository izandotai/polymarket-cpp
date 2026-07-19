#include "net/tls.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef _WIN32
#include <windows.h>

#include <wincrypt.h>
#endif

namespace pm::net {

namespace ssl = boost::asio::ssl;

namespace {

#ifdef _WIN32
    void load_root_certs(ssl::context& ctx)
    {
        X509_STORE* store = SSL_CTX_get_cert_store(ctx.native_handle());
        HCERTSTORE hstore = CertOpenSystemStoreA(0, "ROOT");
        if (!hstore)
            return;
        PCCERT_CONTEXT cert = nullptr;
        while ((cert = CertEnumCertificatesInStore(hstore, cert))) {
            const unsigned char* p = cert->pbCertEncoded;
            if (X509* x = d2i_X509(nullptr, &p, long(cert->cbCertEncoded))) {
                X509_STORE_add_cert(store, x);
                X509_free(x);
            }
        }
        CertCloseStore(hstore, 0);
    }
#else
    void load_root_certs(ssl::context& ctx)
    {
        SSL_CTX_set_default_verify_paths(ctx.native_handle());
    }
#endif

}

ssl::context& tls_context()
{
    static ssl::context ctx = [] {
        ssl::context c(ssl::context::tls_client);
        c.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2
            | ssl::context::no_sslv3 | ssl::context::no_tlsv1
            | ssl::context::no_tlsv1_1);
        c.set_verify_mode(ssl::verify_peer);
        load_root_certs(c);
        return c;
    }();
    return ctx;
}

}
