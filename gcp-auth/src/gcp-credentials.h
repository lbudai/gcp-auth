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

#ifndef GCP_CREDENTIALS_H_INCLUDED
#define GCP_CREDENTIALS_H_INCLUDED

typedef struct _GcpCredentials GcpCredentials;

GcpCredentials* gcp_cred_new(const char *gcp_credentials_str);
void gcp_cred_free(GcpCredentials *self);

const char* gcp_cred_type(const GcpCredentials *self);
const char* gcp_cred_project_id(const GcpCredentials *self);
const char* gcp_cred_private_key_id(const GcpCredentials *self);
const char* gcp_cred_private_key(const GcpCredentials *self);
const char* gcp_cred_client_email(const GcpCredentials *self);
const char* gcp_cred_client_id(const GcpCredentials *self);
const char* gcp_cred_auth_uri(const GcpCredentials *self);
const char* gcp_cred_token_uri(const GcpCredentials *self);
const char* gcp_cred_auth_provider_x509_cert_url(const GcpCredentials *self);
const char* gcp_cred_client_x509_cert_url(const GcpCredentials *self);

#endif

