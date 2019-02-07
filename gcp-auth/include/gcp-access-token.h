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

#ifndef GCP_AUTH_H_INCLUDED
#define GCP_AUTH_H_INCLUDED

typedef struct _GcpAccessToken GcpAccessToken;

GcpAccessToken *gcp_access_token_new(const char *credentials_json_path, const char *scope);
void gcp_access_token_free(GcpAccessToken *self);

void gcp_access_token_set_request_timeout(GcpAccessToken *self, long timeout);
int gcp_access_token_request(GcpAccessToken *self);
const char *gcp_access_token_to_string(GcpAccessToken *self);
unsigned gcp_access_token_get_lifetime(GcpAccessToken *self);
//int gcp_access_token_verify(GcpAccessToken *self); TODO

#endif
