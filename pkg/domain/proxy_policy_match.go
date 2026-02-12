package domain

import (
	"fmt"
	"net/http"
	"regexp"
)

type ProxyPolicyMatch struct {
	Host        string            `json:",omitempty"`
	Method      string            `json:",omitempty"`
	Path        string            `json:",omitempty"`
	Scheme      string            `json:",omitempty"`
	Header      map[string]string `json:",omitempty"` // Header name -> regex pattern
	Query       map[string]string `json:",omitempty"` // Query param name -> regex pattern
	Fragment    string            `json:",omitempty"`
	ContentType string            `json:",omitempty"`

	host        *regexp.Regexp
	method      *regexp.Regexp
	path        *regexp.Regexp
	scheme      *regexp.Regexp
	header      map[string]*regexp.Regexp
	query       map[string]*regexp.Regexp
	fragment    *regexp.Regexp
	contentType *regexp.Regexp
}

func (p *ProxyPolicyMatch) Match(r *http.Request) bool {
	if p.host != nil && !p.host.MatchString(r.Host) {
		return false
	}
	if p.method != nil && !p.method.MatchString(r.Method) {
		return false
	}
	if p.path != nil && !p.path.MatchString(r.URL.Path) {
		return false
	}
	if p.scheme != nil && !p.scheme.MatchString(r.URL.Scheme) {
		return false
	}
	if p.fragment != nil && !p.fragment.MatchString(r.URL.Fragment) {
		return false
	}
	if p.contentType != nil {
		ct := r.Header.Get("Content-Type")
		if !p.contentType.MatchString(ct) {
			return false
		}
	}
	for name, re := range p.header {
		value := r.Header.Get(name)
		if !re.MatchString(value) {
			return false
		}
	}
	for name, re := range p.query {
		value := r.URL.Query().Get(name)
		if !re.MatchString(value) {
			return false
		}
	}
	return true
}

func (p *ProxyPolicyMatch) Compile() (err error) {
	if p.Host != "" {
		p.host, err = regexp.Compile(p.Host)
		if err != nil {
			return fmt.Errorf("compile proxy policy host regexp: %w", err)
		}
	}
	if p.Method != "" {
		p.method, err = regexp.Compile(p.Method)
		if err != nil {
			return fmt.Errorf("compile proxy policy method regexp: %w", err)
		}
	}
	if p.Path != "" {
		p.path, err = regexp.Compile(p.Path)
		if err != nil {
			return fmt.Errorf("compile proxy policy path regexp: %w", err)
		}
	}
	if p.Scheme != "" {
		p.scheme, err = regexp.Compile(p.Scheme)
		if err != nil {
			return fmt.Errorf("compile proxy policy ports regexp: %w", err)
		}
	}
	if p.Fragment != "" {
		p.fragment, err = regexp.Compile(p.Fragment)
		if err != nil {
			return fmt.Errorf("compile proxy policy fragment regexp: %w", err)
		}
	}
	if p.ContentType != "" {
		p.contentType, err = regexp.Compile(p.ContentType)
		if err != nil {
			return fmt.Errorf("compile proxy policy content-type regexp: %w", err)
		}
	}
	if len(p.Header) > 0 {
		p.header = make(map[string]*regexp.Regexp)
		for name, pattern := range p.Header {
			p.header[name], err = regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("compile proxy policy header[%s] regexp: %w", name, err)
			}
		}
	}
	if len(p.Query) > 0 {
		p.query = make(map[string]*regexp.Regexp)
		for name, pattern := range p.Query {
			p.query[name], err = regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("compile proxy policy query[%s] regexp: %w", name, err)
			}
		}
	}
	return nil
}
