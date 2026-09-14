'use strict';
// tests/fixtures/testCert.js
//
// A throwaway self-signed certificate + key, generated once for the unit tests
// in tests/certValidate.test.js.
//
// ⛔ THIS PRIVATE KEY IS PUBLIC. It is committed to a repository and must never
// be used to serve anything. It exists so the "wrong key" test can use a
// genuinely different key rather than a corrupted string, which would fail for
// the wrong reason and prove nothing.
//
// CN=localhost, SANs DNS:localhost + IP:127.0.0.1, valid for 10 years from
// 2026-09-14 — long enough that the suite does not start failing on a date.

const cert = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUacn0plyQdN9QN0Pz4CDIlMQGHKowDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkxNDA0MzE0OVoXDTM2MDkx
MTA0MzE0OVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAr28U0ZJSmEYMefJH/xmXMQ4KxBwiuBA4IyTGAOf//6Mr
fSZkVVqwbbiiME7DEC8867yNqIW77M+F+fV96h4Habw0F8NDcSSgfZuUP344HOXH
UOUCxi7o0mqIci4Zkphx5+/cgJZ2OakmXeXDXGa1tWJrHpose+M2j8dNPWHLM4ji
aNOzj8D3Ctol6z6zPcbV2QsQROx5DaMqY+9Qq5+ezFMbbhWcxd+RjhHycr42xtsF
wogWaEuFYpJfyHA21qzMzz+/VRPSOUdDQzvLMOP8VbowsSR7hbjuVo47KYucffJ1
rdo7ccZpKbTRoa0uyLX6HyXJDEEcYtG4EiLLpgT0qQIDAQABo28wbTAdBgNVHQ4E
FgQUTrAciNaf3Sp0oLSVWT22KoFyCHwwHwYDVR0jBBgwFoAUTrAciNaf3Sp0oLSV
WT22KoFyCHwwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAJ5FKINe3t797/RHH/ODqU28/4qeW1cY
efqXybFknL2EI7GEi/WYc0eYEHIsKWyq8og3IzS3VZx46JQRwPE4w8NSHopFnh6o
hXgbshUPOD5q366kDP01rXceggQENwseaLJ+8MwjXcGg9XNGN/5tRRaw0d01OQtx
Tgd6lNp09eaWtuAMnmIVzGUviVsjYMy/eyib1pVto9WHsLTEoMetOb3A+4UEZVUF
hCq+zFSYBT+RaEMrCNyuT5ncHPOyoKu76zqlNmtZq/cpSapxqwc8j4UPmNlMXZDF
MK9qY2d/PDRKuH/JwWAWI5m6VHqm1NxuCNjmka3Iu7xMsugoTUBGjW8=
-----END CERTIFICATE-----`;

const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvbxTRklKYRgx5
8kf/GZcxDgrEHCK4EDgjJMYA5///oyt9JmRVWrBtuKIwTsMQLzzrvI2ohbvsz4X5
9X3qHgdpvDQXw0NxJKB9m5Q/fjgc5cdQ5QLGLujSaohyLhmSmHHn79yAlnY5qSZd
5cNcZrW1Ymsemix74zaPx009YcsziOJo07OPwPcK2iXrPrM9xtXZCxBE7HkNoypj
71Crn57MUxtuFZzF35GOEfJyvjbG2wXCiBZoS4Vikl/IcDbWrMzPP79VE9I5R0ND
O8sw4/xVujCxJHuFuO5Wjjspi5x98nWt2jtxxmkptNGhrS7ItfofJckMQRxi0bgS
IsumBPSpAgMBAAECggEAC3Ny9q34Ha/e0xvlJqnPNFjAC6ZxfrWyUFrvYLJEA7Xt
GgVmQasCfprxXTla4qTOs21yiqg2CMJP8q2bOyucHML33IA2l/1Fy4Ua810EASDf
dnCIUpLPyCJDhz5qlWbFcpf1ut/3VhKsKi9b5d1faXhD2TLDig+d6VsfN805FAM0
1H58aDfEhdAPWytpzL5qZ1l1fPSlj0CrJnJ7P+qyqz1U2igmREQRCy4zH06nKauL
5my+1O64+zCDocxEKWoPKMBdI6lh+6wNE9e/mrXZIT7c51GdrxxRxo9kBcElbDJv
H8v0LFfmbuRr3hZQXM+sS9DCNXpjj3ewAFAsGMFsoQKBgQDkGLqF1JumsrNdVZNr
kRGbasWhddRLvPwlLGDKyQLAM28hqJOJ/4DwlwjZow0eHVeMtNQYG+TdXs4Kew9B
fyTlFrta1+WlE6HN1pg4Na36+UtAWaJgBgBBH0cDAc8/Mwx7JNSZ4Om5OkBRc5KU
52eTHfY2CPsS98Y4fVgTYBInGQKBgQDE5R9NvFUKWfEfb21fZMMLIz/VB09xSh2f
hO2HhaW8gSmCcTO2I/3PyyPUTchgrkI5IFYB0ZEbMNhY0H1AleupX8Qtq3vYjbLw
TnkHIIbhO+Db5N/1XUfYtxTLnlKX8xma8x8oF/TsNhSRvnP7X9SY6mllyTvFadVL
ySU9diq8EQKBgQDbJRsHe4Xz+Zq0YISbgywsar/n6WIHRlHmkSWJjuhyqrfp2aGu
oulJvYJGPw5aUYyM5isj4qDXQr+oeCTnI3XaGCX3GJhNKnh5X+StlH1MNHllIPkN
Upap+pfqPrHUIYKrSW5tTRag3GNxHh3FrDHpuY6UyboXtjAek+ar7tBh+QKBgGSd
eTuuK/7YK2GW/VssEIeWgb4IuE36Q90Kfp8sap9DmcSwuG4xQjh3ZF3PScAuDGVI
4uqW/wHYGhZ4pCjm88Bf0c5MvULSVkh6sVo1AvgCM0vrT48BFf/mvte2lhpT/hey
eY9xfpVepXA81OP1+pwR3b5H8SVWicrqhP89bWUhAoGALJPJG1i4q7blS0IQH8qd
wmbmX1FpqMzJ83v0VkqsNUdBilnNaam5nXmO5nEjJfg+Wcdx9I3DyLbrgq2CsF7A
kLpKGuRIsUn1eLc9F1GcRRfYJBWrWF6cvQ7mkNiXo/ZTQRnCorVlOiJqUBOyY0QA
AzTDinRa4T8jru1HCHsWlAU=
-----END PRIVATE KEY-----`;

module.exports = { cert, key };
