/*
 * Copyright (c) 2019 Budai Laszlo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "jwt.h"
#include "asprintf-compat.h"
#include <stddef.h>
#include <string.h>
#include "openssl-compat.h"
#include <openssl/bio.h>

static EVP_PKEY*
_load_pkey_from_pem_str(const char *pem)
{
  BIO *pem_bio = BIO_new_mem_buf(pem, -1);
  if (!pem_bio)
    return NULL;

  EVP_PKEY *key = PEM_read_bio_PrivateKey(pem_bio, NULL, NULL, NULL);
  BIO_free(pem_bio);

  return key;
}

static unsigned int
_evp_digest(const EVP_MD *md, const char *msg, unsigned char *md_value)
{
  unsigned int md_len = 0;
  DECLARE_EVP_MD_CTX(ctx);
  EVP_MD_CTX_init(ctx);

  if(EVP_DigestInit_ex(ctx, md, NULL) != 1)
    goto exit;

  if(EVP_DigestUpdate(ctx, (const unsigned char *)msg, strlen(msg)) != 1)
    goto exit;

  if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1)
    goto exit;

exit:
  EVP_MD_CTX_cleanup(ctx);
  EVP_MD_CTX_destroy(ctx);
  return md_len;
}

static unsigned int
_evp_sha256_digest(const char *msg, unsigned char *md_value)
{
  return _evp_digest(EVP_sha256(), msg, md_value);
}

static unsigned int
_jwt_digest(JWT_ALG alg, const char *msg, unsigned char *md_value)
{
  switch (alg)
  {
    case JWT_ALG_RS256: return _evp_sha256_digest(msg, md_value);
    default: return 0; //TODO: error msg
  }
  return 0;
}

static size_t
_evp_digest_sign(const EVP_MD *md, EVP_PKEY *key, const char *msg, unsigned char **sig)
{
  size_t siglen = 0;

  DECLARE_EVP_MD_CTX(ctx);
  EVP_MD_CTX_init(ctx);
  if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1)
    goto exit;

  if(EVP_DigestSignUpdate(ctx, (const unsigned char *)msg, strlen(msg)) != 1)
    goto exit;

  if (EVP_DigestSignFinal(ctx, NULL, &siglen) != 1)
    goto exit;

  if (!(*sig = OPENSSL_malloc(sizeof(unsigned char) * siglen)))
    goto exit;

  if (EVP_DigestSignFinal(ctx, *sig, &siglen) != 1)
    goto exit;

exit:
  EVP_MD_CTX_cleanup(ctx);
  EVP_MD_CTX_destroy(ctx);
  return siglen;
}

static size_t
_jwt_digest_sign(JWT_ALG alg, EVP_PKEY *key, const char *msg, unsigned char **sig)
{
  switch (alg)
  {
    case JWT_ALG_RS256: return _evp_digest_sign(EVP_sha256(), key, msg, sig);
    default: return 0;
  }
  return 0;
}

static const char *JWT_ALG_str[] = 
{
  "RS256"
};

static const char *
_jwt_alg_lookup_str(JWT_ALG alg)
{
  if (alg > JWT_ALG_MAX)
    return NULL;

  return JWT_ALG_str[alg];
}

static char *
_base64(const unsigned char *input, int input_len)
{
  int res;
	BIO *bio_mem, *bio_b64;
	BUF_MEM *internal_buf;
	char *b64_str;

	bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	bio_mem = BIO_new(BIO_s_mem());
	bio_b64 = BIO_push(bio_b64, bio_mem);
	
	BIO_write(bio_b64, input, input_len);
	res = BIO_flush(bio_b64);
	if(res < 1) 
    {
	  	BIO_free_all(bio_b64);
  		return NULL;
  	}

  BIO_get_mem_ptr(bio_b64, &internal_buf);

	b64_str = (char *) malloc(internal_buf->length + 1);
	memcpy(b64_str, internal_buf->data, internal_buf->length);
	b64_str[internal_buf->length] = '\0';

	BIO_free_all(bio_b64);
	return b64_str;
}

static char * 
_base64_urlsafe(char *b64)
{
  size_t len = strlen(b64);
  for (size_t i = 0; i < len; i++)
    {
      switch (b64[i])
      {
        case '+' : b64[i] = '-'; break;
        case '/' : b64[i] = '_'; break;
        case '=' : b64[i] = '\0'; break; //TODO: '\r\n...'
        default: break;
      }
    }

  return b64;
}

static char *
_header_b64(const char *alg_str)
{
  char header[256] = {'\0'};
  int header_len = snprintf(header, sizeof(header), "{\"alg\":\"%s\",\"typ\":\"JWT\"}", alg_str);

  return _base64_urlsafe(_base64((const unsigned char *)header, header_len));
}

static char * 
_concat_header_with_payload(const char *header, const char *payload)
{
  char *res = NULL;
  if (asprintf(&res, "%s.%s", header, payload) < 0)
    return NULL;

  return res;
}

static char *
_build_header_with_payload_b64(const char *alg_str, const char *payload_json)
{
  char *header_b64 = _header_b64(alg_str);
  char *payload_b64 = _base64_urlsafe(_base64((const unsigned char *)payload_json, strlen(payload_json)));
  char *res = _concat_header_with_payload(header_b64, payload_b64);
  free(header_b64);
  free(payload_b64);

  return res;
}

char *jwt_encode(JWT_ALG alg, const char *pem_key, const char *payload_json)
{
  char *jwt_str = NULL;
  unsigned char *sig = NULL;
  char *sig_b64 = NULL;
  char *header_with_payload_b64 = NULL;
  EVP_PKEY *key = _load_pkey_from_pem_str(pem_key);
  if (!key)
    return NULL;

  const char *alg_str = _jwt_alg_lookup_str(alg);
  if (!alg_str)
    goto exit;

  header_with_payload_b64 = _build_header_with_payload_b64(alg_str, payload_json);
  size_t siglen = _jwt_digest_sign(alg, key, header_with_payload_b64, &sig);
  sig_b64 = _base64_urlsafe(_base64(sig, siglen));
  jwt_str = _concat_header_with_payload(header_with_payload_b64, sig_b64);

exit:
 if (header_with_payload_b64)
    free(header_with_payload_b64);
  EVP_PKEY_free(key);
  if (sig_b64)
    free(sig_b64);
  if (sig)
    OPENSSL_free(sig);

  return jwt_str;
}
