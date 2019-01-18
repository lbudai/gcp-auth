#include "jwt.h"
#include <stddef.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

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
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if(EVP_DigestInit_ex(ctx, md, NULL) != 1)
    goto exit;

  if(EVP_DigestUpdate(ctx, (const unsigned char *)msg, strlen(msg)) != 1)
    goto exit;

  if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1)
    goto exit;

exit:
  EVP_MD_CTX_free(ctx);
  return md_len;
}

static unsigned int
_evp_sha256_digest(const char *msg, unsigned char *md_value)
{
  return _evp_digest(EVP_sha256(), msg, md_value);
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
_base64(const char *input, int input_len)
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

  return _base64_urlsafe(_base64(header, header_len));
}

static char * 
_concat_header_with_payload(const char *header, const char *payload)
{
  size_t len = strlen(header) + 1 + strlen(payload) + 1;//header64.payload64
  char *res = malloc(len);
  res[len - 1] = '\0';

  sprintf(res, "%s.%s", header, payload);

  return res;
}

static char *
_build_header_with_payload_b64(const char *alg_str, const char *payload_json)
{
  char *header_b64 = _header_b64(alg_str);
  char *payload_b64 = _base64_urlsafe(_base64(payload_json, strlen(payload_json)));
  char *res = _concat_header_with_payload(header_b64, payload_b64);

  free(header_b64);
  free(payload_b64);

  return res;
}

char *jwt_encode(JWT_ALG alg, const char *pem_key, const char *payload_json)
{
  EVP_PKEY *key = _load_pkey_from_pem_str(pem_key);
  if (!key)
    return NULL;

  const char *alg_str = _jwt_alg_lookup_str(alg);
  if (!alg_str)
    goto exit;

  char *header_with_payload_b64 = _build_header_with_payload_b64(alg_str, payload_json); 
 
  fprintf(stderr, "ehune:[%s]\n", header_with_payload_b64);

exit:
 if (header_with_payload_b64)
    free(header_with_payload_b64);
  EVP_PKEY_free(key);
  return NULL;
}
