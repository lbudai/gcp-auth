# gcp-auth

A simple/example library for getting an access token for a GCP (google cloud platform) project.

## library
 
 * build [JWT](https://jwt.io/) (dependency: `OpenSSL`)
 * parse a JSON [service account credentials file](https://cloud.google.com/docs/authentication/production) (dependency: `json-c-0.13`)
 * send a token request message to the token_uri (dependency: `libCurl`)
 
### main limitation
 * only one algorithm (`RS256`) is supported currently (but it is easy to extend the list)

### build
 * check [Travis yaml script](.travis.yml)
 * Why I need to use [OBS](https://build.opensuse.org/project/show/home:laszlo_budai:syslog-ng) repository?
     * When the JWT is encoded, forward slashed should not be escaped, so the code depend on the `JSON_C_TO_STRING_NOSLASHESCAPE`. [More details](https://github.com/json-c/json-c/issues/201) . This feature is release in version 0.13.
     * I'm using the [Criterion](https://github.com/Snaipe/Criterion) unit test framework, which is not part of Ubuntu.
     
## binary tool

```
goauth -c ../../service-account/lbudai-test-project-xxxxx.json -s https://www.googleapis.com/auth/logging.write
```
