package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/oauth2_proxy/cookie"
)

func (p *ProviderData) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	if p.ClientSecret != "" {
		params.Add("client_secret", p.ClientSecret)
	}
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, c_err := http.DefaultClient.Do(req)
	var body []byte
	body, b_err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if b_err != nil {
		return
	}
	if c_err != nil {
		log.Printf("headers from failed redemption are %s", resp.Header)
		log.Printf("body from failed redemption is %s", body)
		return nil, c_err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, finalRedirect string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	if strings.HasPrefix(finalRedirect, "/") {
		params.Add("state", finalRedirect)
	}
	a.RawQuery = params.Encode()
	return a.String()
}

// CookieForSession serializes a session state for storage in a cookie
func (p *ProviderData) CookieForSession(s *SessionState, c *cookie.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func (p *ProviderData) SessionFromCookie(v string, c *cookie.Cipher) (s *SessionState, err error) {
	return DecodeSessionState(v, c)
}

func (p *ProviderData) GetEmailAddress(s *SessionState) (string, error) {
	return "", errors.New("not implemented")
}

func (p *ProviderData) GetGroups(s *SessionState, f string) (string, error) {
	return "", errors.New("not implemented")
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *ProviderData) ValidateGroup(email string) bool {
	return true
}

func (p *ProviderData) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded
func (p *ProviderData) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	return false, nil
}
