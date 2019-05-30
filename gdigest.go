// Copyright 2019 Marco Conti
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gdigest

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// Algorithm & Quality of protection hashing options
const (
	AlgUnspec = ""
	AlgMD5    = "MD5"
	AlgSess   = "MD5-sess"
	QopUnspec = ""
	QopAuth   = "auth"
	QopInt    = "auth-int"
)

// Possible errors
var (
	ErrAuthStatus  = errors.New("status code 401 expected")
	ErrAuthHeader  = errors.New("no www-authenticate response header found")
	ErrAuthInvalid = errors.New("www-authenticate is invalid")
	ErrAlgInvalid  = errors.New("invalid algorithm")
	ErrQopInvalid  = errors.New("invalid qop")
)

// Digest stores authentication parameters
type Digest struct {
	user      string
	pass      string
	host      string
	realm     string
	nonce     string
	algorithm string
	qop       string
	nc        uint64
	cnonce    string
	response  string
	opaque    string
}

// Request is a custom http.Request
type Request struct {
	*http.Request
}

// NewDigest returns reference of Digest
func NewDigest(user string, pass string, host string) *Digest {
	return &Digest{
		user: user,
		pass: pass,
		host: host,
	}
}

// NewRequest reflects http.NewRequest and returns a *DigestRequest
func NewRequest(method, url string, body io.Reader) (*Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	return &Request{request}, nil
}

// Do returns the generated auth string for given values for your next requests authorization header.
// Simply skip supplying a body parameter (leave empty) if you know your server does not make use of qop=auth-int
func (d *Digest) Do(uri string, method string, body string) (string, error) {

	h, err := d.authHeader(d.host, uri)
	if err != nil {
		return "", err
	}

	d.realm = d.readParam(h, "realm")
	d.nonce = d.readParam(h, "nonce")
	d.qop = d.readParam(h, "qop")
	d.opaque = d.readParam(h, "opaque")
	d.algorithm = d.readParam(h, "algorithm") // Unsure if can be set by server; fallback to AlgMD5
	d.cnonce = d.genCNonce()                  // Generate per request

	if !d.validAlg(d.algorithm) {
		return "", ErrAlgInvalid
	}

	if d.algorithm == "" {
		d.algorithm = AlgMD5
	}

	if !d.validQop(d.qop) {
		return "", ErrQopInvalid
	}

	ha1 := d.hash(fmt.Sprintf("%s:%s:%s", d.user, d.realm, d.pass))
	ha2 := d.hash(fmt.Sprintf("%s:%s", method, uri))

	if d.algorithm == AlgSess {
		ha1 = d.hash(fmt.Sprintf("%s:%s:%s", ha1, d.nonce, d.cnonce))
	}

	if d.qop == QopInt {
		ha2 = d.hash(fmt.Sprintf("%s:%s:%s", method, uri, d.hash(body)))
	}

	d.response = d.hash(fmt.Sprintf("%s:%s:%s", ha1, d.nonce, ha2))
	if d.qop == QopAuth || d.qop == QopInt {
		d.response = d.hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, d.nonce, d.getNonceCount(true), d.cnonce, d.qop, ha2))
	}

	return d.format(uri), nil
}

// getNonceCount returns formatted nonce counter
func (d *Digest) getNonceCount(inc bool) string {
	if inc {
		d.nc++
	}
	return fmt.Sprintf("%08d", d.nc)
}

// format returns authorization header
func (d *Digest) format(uri string) string {
	return fmt.Sprintf(
		"Digest realm=\"%s\",nonce=\"%s\",algorithm=\"%s\",qop=\"%s\",nc=\"%s\",cnonce=\"%s\",response=\"%s\",opaque=\"%s\",uri=\"%s\",username=\"%s\"",
		d.realm,
		d.nonce,
		d.algorithm,
		d.qop,
		d.getNonceCount(false),
		d.cnonce,
		d.response,
		d.opaque,
		uri,
		d.user,
	)
}

// authHeader queries the destination endpoint to retrieve www-authenticate header
func (d *Digest) authHeader(host string, uri string) (string, error) {

	req, err := http.NewRequest("GET", host+uri, nil)
	if err != nil {
		return "", err
	}

	client := http.Client{}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		return "", ErrAuthStatus
	}

	if len(res.Header["Www-Authenticate"]) == 0 {
		return "", ErrAuthHeader
	}

	str := res.Header["Www-Authenticate"][0]
	if !strings.HasPrefix(str, "Digest ") {
		return "", ErrAuthInvalid
	}

	return strings.Replace(str, "Digest ", "", 1), nil
}

// readParam extracts parameter value of given www authentication header string
func (d *Digest) readParam(header string, name string) string {
	for _, head := range strings.Split(header, ",") {
		kvs := strings.Split(head, "=")
		if len(kvs) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(kvs[0])) == strings.ToLower(name) {
			val := strings.TrimSpace(kvs[1])
			val = strings.TrimPrefix(val, "\"")
			val = strings.TrimSuffix(val, "\"")
			return val
		}
	}
	return ""
}

// hash returns the md5-hash of given string
func (d *Digest) hash(text string) string {
	alg := md5.New()
	_, err := alg.Write([]byte(text))
	if err != nil {
		log.Println(err.Error())
	}
	return hex.EncodeToString(alg.Sum(nil))
}

// genCNonce generates a new genCNonce
func (d *Digest) genCNonce() string {
	b := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}

// validAlg checks for valid quality of algorithm
func (d *Digest) validAlg(alg string) bool {
	for _, a := range []string{AlgUnspec, AlgMD5, AlgSess} {
		if strings.ToLower(a) == strings.ToLower(alg) {
			return true
		}
	}
	return false
}

// validQop checks for valid quality of protection
func (d *Digest) validQop(alg string) bool {
	for _, a := range []string{QopUnspec, QopAuth, QopInt} {
		if strings.ToLower(a) == strings.ToLower(alg) {
			return true
		}
	}
	return false
}

// SetDigestAuth enables digest authentication
func (r *Request) SetDigestAuth(user, pass, host, uri, method, body string) error {
	digest := NewDigest(user, pass, host)
	str, err := digest.Do(uri, method, body)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", str)
	return nil
}
