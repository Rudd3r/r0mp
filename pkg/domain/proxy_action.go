package domain

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type ActionModify struct {
	Name string
	Args []string
}

func proxyActionModifySetHeader(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("proxy action modify requires 2 argument")
	}
	return func(r *http.Request) error {
		r.Header.Set(args[0], args[1])
		return nil
	}, nil
}

func proxyActionModifyPath(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	return func(r *http.Request) error {
		r.URL.Path = args[0]
		return nil
	}, nil
}

func proxyActionModifyHost(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	return func(r *http.Request) error {
		r.Host = args[0]
		r.URL.Host = args[0]
		return nil
	}, nil
}

func proxyActionModifyAuthBearer(args []string, secretstore SecretReadWriter) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	return func(r *http.Request) error {
		if secretstore == nil {
			return fmt.Errorf("secret store is nil, cannot retrieve bearer token")
		}
		token, err := secretstore.GetSecret(args[0])
		if err != nil {
			return fmt.Errorf("proxy token %s not found", args[0])
		}
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}, nil
}

func proxyActionModifyDeleteHeader(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	return func(r *http.Request) error {
		r.Header.Del(args[0])
		return nil
	}, nil
}

func proxyActionModifyAddPathPrefix(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	prefix := args[0]
	return func(r *http.Request) error {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			r.URL.Path = prefix + r.URL.Path
		}
		return nil
	}, nil
}

func proxyActionModifyRemovePathPrefix(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	prefix := args[0]
	return func(r *http.Request) error {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		return nil
	}, nil
}

func proxyActionModifySetBasicAuth(args []string, secretstore SecretReadWriter) (func(r *http.Request) error, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("proxy action modify requires 2 arguments")
	}
	return func(r *http.Request) error {
		if secretstore == nil {
			return fmt.Errorf("secret store is nil, cannot retrieve basic auth password")
		}
		password, err := secretstore.GetSecret(args[1])
		if err != nil {
			return fmt.Errorf("proxy basic auth password %s not found", args[1])
		}
		r.SetBasicAuth(args[0], password)
		return nil
	}, nil
}

func proxyActionModifyAddQueryParam(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("proxy action modify requires 2 arguments")
	}
	key, value := args[0], args[1]
	return func(r *http.Request) error {
		q := r.URL.Query()
		q.Add(key, value)
		r.URL.RawQuery = q.Encode()
		return nil
	}, nil
}

func proxyActionModifySetQueryParam(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("proxy action modify requires 2 arguments")
	}
	key, value := args[0], args[1]
	return func(r *http.Request) error {
		q := r.URL.Query()
		q.Set(key, value)
		r.URL.RawQuery = q.Encode()
		return nil
	}, nil
}

func proxyActionModifyDeleteQueryParam(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	key := args[0]
	return func(r *http.Request) error {
		q := r.URL.Query()
		q.Del(key)
		r.URL.RawQuery = q.Encode()
		return nil
	}, nil
}

func proxyActionModifySetScheme(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("proxy action modify requires 1 argument")
	}
	scheme := args[0]
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	return func(r *http.Request) error {
		r.URL.Scheme = scheme
		return nil
	}, nil
}

func proxyActionModifyRewritePath(args ...string) (func(r *http.Request) error, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("proxy action modify requires 2 arguments")
	}
	pattern, replacement := args[0], args[1]
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	return func(r *http.Request) error {
		r.URL.Path = re.ReplaceAllString(r.URL.Path, replacement)
		return nil
	}, nil
}
