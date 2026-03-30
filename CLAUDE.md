# ntlmssp

Pure Go NTLM SSP with NTLMv2, signing/sealing (RC4), and HTTP auth wrapper.

## Packages

ntlmssp/   — Core NTLM client: negotiate, challenge, authenticate
http/      — HTTP client wrapper with NTLM auth dance

## Core Client

```go
c, _ := ntlmssp.NewClient(
    ntlmssp.SetDomain("DOMAIN"),
    ntlmssp.SetUserInfo("user", "pass"),
    ntlmssp.SetWorkstation("HOST"),
    ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
)

negotiate, _ := c.Authenticate(nil, nil)         // step 1: generate NEGOTIATE
authenticate, _ := c.Authenticate(challenge, nil) // step 2: generate AUTHENTICATE
session := c.SecuritySession()                    // available when c.Complete()
sealed, sig, _ := session.Wrap(msg)
plain, _ := session.Unwrap(sealed, sig)
c.Reset()  // clear session state, keep credentials

ChannelBindings — pass TLS peer cert hash for CBT (MITM protection).

HTTP Client (http/)

Client — wraps *http.Client + *ntlmssp.Client:
- NewClient(httpClient, ntlmClient, options...) — nil httpClient → cleanhttp.DefaultClient()
- Do(req) — handles full NTLM auth dance; body present on all three legs
- RoundTrip(req) — implements http.RoundTripper
- Options: Encryption(bool), SendCBT(bool), Logger(logr.Logger)

Auth flow in Do():
1. If ntlm.Complete(): wrap body, send, handle 401 by Reset() and fall through
2. Send request (gets 401 with Negotiate challenge)
3. Loop ≤2 times: extract token → Authenticate() → set Authorization header → drain body → reset body+ContentLength → send → break on non-401
4. Return auth-200 directly — it IS the real response, no third request

Encryption — wrap()/unwrap() use multipart/encrypted MIME

Requirement: keep-alives must be enabled; NTLM is connection-oriented.
