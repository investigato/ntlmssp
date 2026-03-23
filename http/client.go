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

type Client struct {
	http       *http.Client
	ntlm       *ntlmssp.Client
	encryption bool
	sendCBT    bool
	logger     logr.Logger
}

type teeReadCloser struct {
	io.Reader
	io.Closer
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

		sealed, signature, err := session.Wrap(body)
		if err != nil {
			return err
		}

		length := make([]byte, 4)
		binary.LittleEndian.PutUint32(length, uint32(len(signature)))

		body, newContentType, err := Wrap(concat(length, signature, sealed), contentType)
		if err != nil {
			return err
		}

		req.Body = io.NopCloser(bytes.NewBuffer(body))
		req.Header.Set(contentTypeHeader, newContentType)
	}

	return nil
}

func (c *Client) unwrap(resp *http.Response) error {
	if session := c.ntlm.SecuritySession(); c.ntlm.Complete() && c.encryption && session != nil && resp.Body != nil {

		contentType := resp.Header.Get(contentTypeHeader)
		if contentType == "" {
			return errors.New("no Content-Type header")
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
	//There are 2 paths through this function:
	//Fast path — c.ntlm.Complete() is true (already authenticated)
	if c.ntlm.Complete() {
		if err := c.wrap(req); err != nil {
			return nil, err
		}
		resp, err = c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if err := c.unwrap(resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	c.logger.Info("request", req)
	//Regular path auth it up!
	//1. Read and save the original body bytes and Content-Type header before touching anything
	var savedBody []byte

	if req.Body != nil {
		savedBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	contentType := req.Header.Get(contentTypeHeader)
	//2. Set req.Body = nil (and req.ContentLength = 0) strip the body for the auth dance

	req.Body = nil
	req.ContentLength = 0
	req.GetBody = nil
	c.logger.Info("request", req)

	//3. Send the initial unauthenticated request → expect 401
	resp, err = c.http.Do(req)
	if err != nil {
		return nil, err
	}

	if c.ntlm.Complete() || resp.StatusCode != http.StatusUnauthorized {
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
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		c.logger.Info("request", req)

		//- Send with nil body
		resp, err = c.http.Do(req)
		if err != nil {
			return nil, err
		}
		//- If not 401: break (AUTHENTICATE got 200)
		if resp.StatusCode != http.StatusUnauthorized {
			break
		}
	}
	//5. After loop: drain and close final auth response body
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	//6. Restore previous req.Body
	req.Body = io.NopCloser(bytes.NewReader(savedBody))

	//7. Update the content-lenth to -1 to force chunked encoding (this is what evil-winrm-py does, and it seems to be required for the final payload request to work properly)
	req.ContentLength = -1
	//8. Restore original Content-Type header
	req.Header.Set(contentTypeHeader, contentType)
	//9. Delete the Authorization header, a first authenticated request has no header
	req.Header.Del("Authorization")
	//10. wrap it up
	if err := c.wrap(req); err != nil {
		return nil, err
	}
	c.logger.Info("request", req)
	//11. this is the real payload request
	resp, err = c.http.Do(req)
	if err != nil {
		return nil, err
	}
	//12. unwrap the response if necessary and inspect
	if c.ntlm.Complete() && c.encryption {
		if err := c.unwrap(resp); err != nil {
			return nil, err
		}
	}
	//13. Return
	return resp, nil
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
