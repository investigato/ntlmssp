package http

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/investigato/ntlmssp"
)

var (
	httpAuthenticateHeader = textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")
)
var (
	errChecksumMismatch = errors.New("checksum does not match")
	errSeqNumMismatch   = errors.New("sequence number does not match")
)

type Client struct {
	http       *http.Client
	ntlm       *ntlmssp.Client
	encryption bool
	sendCBT    bool
	logger     logr.Logger
}

func NewClient(httpClient *http.Client, ntlmClient *ntlmssp.Client, options ...func(*Client) error) (*Client, error) {
	if httpClient == nil {
		httpClient = cleanhttp.DefaultClient()
	}
	if httpClient.Jar == nil {
		httpClient.Jar, _ = cookiejar.New(nil)
	}
	if httpClient.Transport != nil && httpClient.Transport.(*http.Transport).DisableKeepAlives {
		return nil, errors.New("NTLM cannot work without keepalives")
	}

	// FIXME CheckRedirect

	if ntlmClient == nil {
		domain, err := ntlmssp.DefaultDomain()
		if err != nil {
			return nil, err
		}

		workstation, err := ntlmssp.DefaultWorkstation()
		if err != nil {
			return nil, err
		}

		ntlmClient, _ = ntlmssp.NewClient(ntlmssp.SetDomain(domain), ntlmssp.SetWorkstation(workstation), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	}

	c := &Client{
		http:   httpClient,
		ntlm:   ntlmClient,
		logger: logr.Discard(),
	}

	if err := c.SetOption(options...); err != nil {
		return nil, err
	}

	return c, nil
}
func (c *Client) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.Do(req)
}
func (c *Client) SetOption(options ...func(*Client) error) error {
	for _, option := range options {
		if err := option(c); err != nil {
			return err
		}
	}
	return nil
}

func SendCBT(value bool) func(*Client) error {
	return func(c *Client) error {
		c.sendCBT = value
		return nil
	}
}

func Encryption(value bool) func(*Client) error {
	return func(c *Client) error {
		c.encryption = value
		return nil
	}
}

func Logger(logger logr.Logger) func(*Client) error {
	return func(c *Client) error {
		c.logger = logger
		return nil
	}
}

func (c *Client) wrap(req *http.Request) error {
	if session := c.ntlm.SecuritySession(); c.ntlm.Complete() && c.encryption && session != nil && req.Body != nil {

		contentType := req.Header.Get(contentTypeHeader)
		if contentType == "" {
			return errors.New("no Content-Type header")
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		bodyLength := len(body)
		sealed, signature, err := session.Wrap(body)
		if err != nil {
			return err
		}

		length := make([]byte, 4)
		binary.LittleEndian.PutUint32(length, uint32(len(signature)))

		// this was originally sending length of the combined payload which led to it being off by 20 bytes (4 bytes for the length field + 16 bytes for the signature)
		body, newContentType, err := Wrap(concat(length, signature, sealed), contentType, bodyLength)
		if err != nil {
			return err
		}

		req.Body = io.NopCloser(bytes.NewBuffer(body))
		req.ContentLength = int64(len(body))
		req.Header.Set(contentTypeHeader, newContentType)
	}

	return nil
}

func (c *Client) unwrap(resp *http.Response) error {
	if session := c.ntlm.SecuritySession(); c.ntlm.Complete() && c.encryption && session != nil && resp.Body != nil {

		contentType := resp.Header.Get(contentTypeHeader)
		if contentType == "" || !strings.HasPrefix(contentType, "multipart/encrypted") {
			return nil
		}

		sealed, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		data, newContentType, err := Unwrap(sealed, contentType)
		if err != nil {
			return err
		}

		length := binary.LittleEndian.Uint32(data[:4])

		signature := make([]byte, length)
		copy(signature, data[4:4+length])

		body, err := session.Unwrap(data[4+length:], signature)
		if err != nil {
			return err
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body))
		resp.Header.Set(contentTypeHeader, newContentType)
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	}

	return nil
}

// refactor all the things!
func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	savedBody, err := saveBody(req)
	if err != nil {
		return nil, err
	}
	originalContentType := req.Header.Get(contentTypeHeader)

	if c.ntlm.Complete() {

		if err := c.wrap(req); err != nil {

			return nil, err
		}

		resp, err = c.http.Do(req)
		if err != nil {
			if !isConnectionError(err) {
				return nil, err
			}
			// connection error: fall through to reset + re-auth
		} else if resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusBadRequest {
			if err := emptyAndCloseBody(resp.Body); err != nil {
				return nil, err
			}
			// fall through to reset + re-auth
		} else {
			if c.encryption {

				if err := c.unwrap(resp); err != nil {
					if !isSessionError(err) {

						return nil, err
					}
					// session error: fall through to reset + re-auth
				} else {

					return resp, nil
				}
			} else {

				return resp, nil
			}
		}
		c.ntlm.Reset()
		req.Body = io.NopCloser(bytes.NewReader(savedBody))
		req.ContentLength = int64(len(savedBody))
		req.Header.Set(contentTypeHeader, originalContentType)
	}
	resp, err = c.http.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		// Potentially unseal and check signature
		if err := c.unwrap(resp); err != nil {
			return nil, err
		}

		return resp, nil
	}
	//4. Loop twice:
	for _ = range [2]int{} {
		//- Extract Negotiate token from response header
		ok, input, err := isAuthenticationMethod(resp.Header, "Negotiate")
		if err != nil {
			return nil, err
		}

		if !ok {
			return resp, nil
		}

		var cbt *ntlmssp.ChannelBindings

		if c.sendCBT && resp.TLS != nil {
			cbt = generateChannelBindings(resp.TLS.PeerCertificates[0]) // Presume it's the first one?
		}
		//- Call c.ntlm.Authenticate(input, cbt) to get next token
		b, err := c.ntlm.Authenticate(input, cbt)
		if err != nil {
			return nil, err
		}

		//- Set Authorization: Negotiate <token>
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(b))

		// Drain and close the previous response body before the next send this is YUUUUUUGE
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			if err = resp.Body.Close(); err != nil {
				return nil, err
			}

			return nil, err
		}
		if err := resp.Body.Close(); err != nil {
			return nil, err
		}

		c.logger.Info("request", req)

		//- Send with nil body
		req.Body = io.NopCloser(bytes.NewReader(savedBody))
		req.ContentLength = int64(len(savedBody))
		if c.ntlm.Complete() && c.encryption {
			if err := c.wrap(req); err != nil {
				return nil, err
			}
		}

		resp, err = c.http.Do(req)
		if err != nil {
			return nil, err
		}
		//- If not 401: break (AUTHENTICATE got 200)
		if resp.StatusCode != http.StatusUnauthorized {
			break
		}
	}
	if c.ntlm.Complete() && c.encryption {
		if err := c.unwrap(resp); err != nil {
			return nil, err
		}
	}
	return resp, nil
}
func isSessionError(err error) bool {
	return errors.Is(err, errChecksumMismatch) || errors.Is(err,
		errSeqNumMismatch)
}
func saveBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	// need to actually put something there...
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func emptyAndCloseBody(body io.ReadCloser) error {
	if _, err := io.Copy(io.Discard, body); err != nil {
		if err = body.Close(); err != nil {
			return err
		}
		return err
	}
	return body.Close()
}

func isConnectionError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "connection reset")
}

func isAuthenticationMethod(headers http.Header, method string) (ok bool, token []byte, err error) {
	if h, ok := headers[httpAuthenticateHeader]; ok {
		for _, x := range h {
			if x == method {
				return true, nil, nil
			}
			if strings.HasPrefix(x, method+" ") {
				parts := strings.SplitN(x, " ", 2)
				if len(parts) < 2 {
					return true, nil, errors.New("malformed " + method + " header value")
				}
				b, err := base64.StdEncoding.DecodeString(parts[1])
				return true, b, err
			}
		}
	}
	return false, nil, nil
}

func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
