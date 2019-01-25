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

#ifndef GCP_JWT_H_INCLUDED
#define GCP_JWT_H_INCLUDED

#include <time.h>

typedef struct _GcpJwt GcpJwt;

GcpJwt *gcp_jwt_new(const char *key);
void gcp_jwt_free(GcpJwt *self);

const char *gcp_jwt_get_encoded(GcpJwt *self);
const char *gcp_jwt_get_json_str(GcpJwt *self, int json_print_str_flags);

void gcp_jwt_set_issuer(GcpJwt *self, const char *iss);
void gcp_jwt_set_scope(GcpJwt *self, const char *scope);
void gcp_jwt_set_audience(GcpJwt *self, const char *aud);
void gcp_jwt_set_issued_at(GcpJwt *self, time_t time);
void gcp_jwt_set_expiration_time(GcpJwt *self, size_t seconds);

#endif
