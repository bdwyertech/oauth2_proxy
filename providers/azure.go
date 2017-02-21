package providers

import (
  "bytes"
	"errors"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/bitly/oauth2_proxy/api"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AzureProvider struct {
	*ProviderData
	Tenant          string
	PermittedGroups []string
}

func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
			Path:   "/v1.0/me",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	if p.ApprovalPrompt == "" || p.ApprovalPrompt == "force" {
		p.ApprovalPrompt = "consent"
	}

	return &AzureProvider{ProviderData: p}
}

func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token"}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
}

func getAzureHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

func (p *AzureProvider) GetEmailAddress(s *SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		log.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

// Get list of groups user belong to. Filter the desired names of groups (in case of huge group set)
func (p *AzureProvider) GetGroups(s *SessionState, f string) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	if s.IDToken == "" {
		return "", errors.New("missing id token")
	}

	// For future use. Right now microsoft graph don't support filter
	// http://docs.oasis-open.org/odata/odata/v4.0/errata02/os/complete/part2-url-conventions/odata-v4.0-errata02-os-part2-url-conventions-complete.html#_Toc406398116

	/*
		var request string = "https://graph.microsoft.com/v1.0/me/memberOf?$select=id,displayName,groupTypes,securityEnabled,description,mailEnabled&$top=999"
		if f != "" {
			request += "?$filter=contains(displayName, '"+f+"')"
		}
	*/
	//
	// Filters that will be possible to use:
	// contains - unknown function | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=contains(displayName,%27groupname%27)"
	// startswith - not supported  | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=startswith(displayName,%27groupname%27)"
	// substring - not supported   | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=substring(displayName,0,2)%20eq%20%27groupname%27"

	requestUrl := "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName"

	groups := make([]string, 0)

	for {
		req, err := http.NewRequest("GET", requestUrl, nil)

		if err != nil {
			return "", err
		}
		req.Header = getAzureHeader(s.AccessToken)
		req.Header.Add("Content-Type", "application/json")

		groupData, err := api.Request(req)
		if err != nil {
			return "", err
		}

		for _, groupInfo := range groupData.Get("value").MustArray() {
			v, ok := groupInfo.(map[string]interface{})
			if !ok {
				continue
			}
			dname := v["displayName"].(string)
			if strings.Contains(dname, f) {
				groups = append(groups, dname)
			}

		}

		if nextlink := groupData.Get("@odata.nextLink").MustString(); nextlink != "" {
			requestUrl = nextlink
		} else {
			break
		}
	}

	return strings.Join(groups, "|"), nil
}

func (p *AzureProvider) GetLoginURL(redirectURI, finalRedirect string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "id_token code")
	params.Set("redirect_uri", redirectURI)
	params.Set("response_mode", "form_post")
	params.Add("scope", p.Scope)
	params.Set("prompt", p.ApprovalPrompt)
	params.Set("nonce", "FIXME")
	if strings.HasPrefix(finalRedirect, "/") {
		params.Add("state", finalRedirect)
	}
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *AzureProvider) SetGroupRestriction(groups []string) {
	p.PermittedGroups = groups
}

func (p *AzureProvider) ValidateGroup(s *SessionState) bool {
	if len(p.PermittedGroups) != 0 {
		for _, pGroup := range p.PermittedGroups {
			if strings.Contains(s.Groups, pGroup) {
				return true
			}
		}
		return false
	}
	return true
}

func (p *AzureProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getAzureHeader(s.AccessToken))
}

//
// Pull Email from ID Token
//
func upnFromIdToken(idToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#jwt-token-claims
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecode(jwt[1])
	if err != nil {
		return "", err
	}

	var upn struct {
		Upn         string `json:"upn"`
	}
	err = json.Unmarshal(b, &upn)
	if err != nil {
		return "", err
	}
	if upn.Upn == "" {
		return "", errors.New("missing UPN")
	}
	return upn.Upn, nil
}

//
// Java Web Token Decoder
//
func jwtDecode(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

//
// Token Redemption
//
func (p *AzureProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IdToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	var email string
	email, err = upnFromIdToken(jsonResponse.IdToken)
	if err != nil {
		return
	}

	s = &SessionState{
		AccessToken:  jsonResponse.AccessToken,
		ExpiresOn:    time.Unix(jsonResponse.ExpiresOn, 0),
		// Refresh Token makes the cookie too large
		// RefreshToken: jsonResponse.RefreshToken,
		Email:        email,
	}
	return
}

//
// Session Refresh
//
func (p *AzureProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, newRefresh, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		return false, err
	}

	// re-check that the user is in the proper Azure group(s)
	// if !p.ValidateGroup(s) {
	// 	return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	// }

	origExpiration := s.ExpiresOn
	s.AccessToken = newToken
	s.RefreshToken = newRefresh
	s.ExpiresOn = time.Now().Add(duration).Truncate(time.Second)
	log.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}

//
// Refresh Token
//
func (p *AzureProvider) redeemRefreshToken(refreshToken string) (token string, refresh string, expires time.Duration, err error) {
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#refreshing-the-access-tokens
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn   int64  `json:"expires_in,string"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	refresh = data.RefreshToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}
