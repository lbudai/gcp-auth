#ifndef OPENSSL_COMPAT_H_INCLUDED
#define OPENSSL_COMPAT_H_INCLUDED

#include <openssl/ssl.h>

#if HAVE_EVP_MD_CTX_RESET
#include <openssl/evp.h>
#define EVP_MD_CTX_cleanup EVP_MD_CTX_reset
#define DECLARE_EVP_MD_CTX(md_ctx) EVP_MD_CTX * md_ctx = EVP_MD_CTX_create()
#else
#define DECLARE_EVP_MD_CTX(md_ctx) EVP_MD_CTX _##md_ctx; EVP_MD_CTX * md_ctx = & _##md_ctx
#define EVP_MD_CTX_destroy(md_ctx) EVP_MD_CTX_cleanup(md_ctx)
#endif

#endif
