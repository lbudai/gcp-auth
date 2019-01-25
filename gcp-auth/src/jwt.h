#ifndef JWT_H_INCLUDED
#define JWT_H_INCLUDED

typedef enum
{
  JWT_ALG_RS256, //TODO:RS384, RS512, ES256, etc...
  JWT_ALG_MAX
} JWT_ALG;

char *jwt_encode(JWT_ALG alg, const char *pem_key, const char *payload_json);

//TODO: jwt_encode(JWT_HMAC_ALG, const char *payload_json);

#endif
