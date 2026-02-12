package args

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
)

type StringValue struct {
	val string
	p   *string
	f   func(val string) (string, error)
}

func NewStringValueFunc(val string, p *string, f func(val string) (string, error)) *StringValue {
	*p = val
	return &StringValue{val: val, p: p, f: f}
}

func (s *StringValue) Set(val string) (err error) {
	s.val, err = s.f(val)
	return err
}
func (s *StringValue) Type() string {
	return "string"
}

func (s *StringValue) String() string { return s.val }

func NewDiskBytes(val int64, i *int64) *StringValue {
	var sizeStr string
	return NewStringValueFunc(domain.FormatSizeBytes(val), &sizeStr, func(s string) (string, error) {
		size, err := domain.ParseSizeBytes(s)
		if err != nil {
			return s, fmt.Errorf("unable to parse disk size, %w", err)
		}
		*i = size
		return s, nil
	})
}

type PortsValue struct {
	ports *[]domain.Ports
}

func NewPortsValue(ports *[]domain.Ports) *PortsValue {
	return &PortsValue{ports: ports}
}

func (p *PortsValue) Set(val string) error {
	port, err := parsePortMapping(val)
	if err != nil {
		return err
	}
	*p.ports = append(*p.ports, port)
	return nil
}

func (p *PortsValue) Type() string {
	return "port"
}

func (p *PortsValue) String() string {
	if p.ports == nil || len(*p.ports) == 0 {
		return ""
	}
	var result []string
	for _, port := range *p.ports {
		if port.GuestIP != "" {
			result = append(result, fmt.Sprintf("%s:%d:%d", port.GuestIP, port.HostPort, port.GuestPort))
		} else {
			result = append(result, fmt.Sprintf("%d:%d", port.HostPort, port.GuestPort))
		}
	}
	return strings.Join(result, ",")
}

func parsePortMapping(s string) (domain.Ports, error) {
	parts := strings.Split(s, ":")

	switch len(parts) {
	case 2:
		hostPort, err := parsePort(parts[0])
		if err != nil {
			return domain.Ports{}, fmt.Errorf("invalid host port: %w", err)
		}
		guestPort, err := parsePort(parts[1])
		if err != nil {
			return domain.Ports{}, fmt.Errorf("invalid guest port: %w", err)
		}
		return domain.Ports{
			HostPort:  hostPort,
			GuestPort: guestPort,
		}, nil

	case 3:
		hostIP := parts[0]
		if net.ParseIP(hostIP) == nil {
			return domain.Ports{}, fmt.Errorf("invalid host IP: %s", hostIP)
		}
		hostPort, err := parsePort(parts[1])
		if err != nil {
			return domain.Ports{}, fmt.Errorf("invalid host port: %w", err)
		}
		guestPort, err := parsePort(parts[2])
		if err != nil {
			return domain.Ports{}, fmt.Errorf("invalid guest port: %w", err)
		}
		return domain.Ports{
			HostPort:  hostPort,
			GuestPort: guestPort,
			GuestIP:   "", // Note: Docker's host IP binding doesn't map to guest IP
		}, nil

	default:
		return domain.Ports{}, fmt.Errorf("invalid port mapping format: %s (expected host_port:guest_port or host_ip:host_port:guest_port)", s)
	}
}

func parsePort(s string) (uint64, error) {
	s = strings.TrimSpace(s)

	// Only TCP is supported; strip /tcp suffix if present, reject /udp
	if strings.HasSuffix(s, "/udp") {
		return 0, fmt.Errorf("UDP port forwarding is not supported (only TCP)")
	}
	s = strings.TrimSuffix(s, "/tcp")

	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", s)
	}
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("port number out of range: %d (must be 1-65535)", port)
	}
	return port, nil
}

// IngressProxyPortsValue handles parsing of ingress proxy port specifications
type IngressProxyPortsValue struct {
	ports *[]domain.IngressProxyPort
}

func NewIngressProxyPortsValue(ports *[]domain.IngressProxyPort) *IngressProxyPortsValue {
	return &IngressProxyPortsValue{ports: ports}
}

func (p *IngressProxyPortsValue) Set(val string) error {
	port, err := parseIngressProxyPort(val)
	if err != nil {
		return err
	}
	*p.ports = append(*p.ports, port)
	return nil
}

func (p *IngressProxyPortsValue) Type() string {
	return "ingress-proxy-port"
}

func (p *IngressProxyPortsValue) String() string {
	if p.ports == nil || len(*p.ports) == 0 {
		return ""
	}
	var result []string
	for _, port := range *p.ports {
		var s string
		if port.PolicyName != "" && port.PolicyName != "allow_all" {
			s = port.PolicyName + "@"
		}
		if port.Scheme != "" && port.Scheme != "http" {
			s += port.Scheme + "://"
		}
		// Omit host IP if it's the default (0.0.0.0)
		if port.HostIP != "" && port.HostIP != "0.0.0.0" {
			s += fmt.Sprintf("%s:%d-%d", port.HostIP, port.HostPort, port.GuestPort)
		} else {
			s += fmt.Sprintf("%d-%d", port.HostPort, port.GuestPort)
		}
		result = append(result, s)
	}
	return strings.Join(result, ",")
}

// parseIngressProxyPort parses ingress proxy port specifications
// Format: [policy@][scheme://][hostip:]hostport-guestport
// Examples:
//   - "mypolicy@https://0.0.0.0:8080-80"
//   - "https://localhost:8443-443"
//   - "0.0.0.0:8080-80"
//   - "127.0.0.1:3000-3000"
//   - "8080-80" (defaults to 0.0.0.0)
//   - "https://8443-443" (defaults to 0.0.0.0)
func parseIngressProxyPort(s string) (domain.IngressProxyPort, error) {
	result := domain.IngressProxyPort{
		PolicyName: "allow_all",
		Scheme:     "http",
		HostIP:     "0.0.0.0", // Default to all interfaces
	}

	remaining := s

	// Extract policy name if present (format: policy@...)
	if idx := strings.Index(remaining, "@"); idx != -1 {
		result.PolicyName = remaining[:idx]
		remaining = remaining[idx+1:]
		if result.PolicyName == "" {
			return domain.IngressProxyPort{}, fmt.Errorf("invalid ingress proxy port: empty policy name before '@'")
		}
	}

	// Extract scheme if present (format: scheme://...)
	if idx := strings.Index(remaining, "://"); idx != -1 {
		result.Scheme = remaining[:idx]
		remaining = remaining[idx+3:]
		if result.Scheme != "http" && result.Scheme != "https" {
			return domain.IngressProxyPort{}, fmt.Errorf("invalid scheme: %s (must be 'http' or 'https')", result.Scheme)
		}
	}

	// Now parse [hostip:]hostport-guestport
	// First, split by '-' to separate host part from guest port
	dashIdx := strings.LastIndex(remaining, "-")
	if dashIdx == -1 {
		return domain.IngressProxyPort{}, fmt.Errorf("invalid ingress proxy port format: %s (expected [policy@][scheme://][hostip:]hostport-guestport)", s)
	}

	hostPart := remaining[:dashIdx]
	guestPortStr := remaining[dashIdx+1:]

	// Parse guest port
	guestPort, err := parsePort(guestPortStr)
	if err != nil {
		return domain.IngressProxyPort{}, fmt.Errorf("invalid guest port: %w", err)
	}
	result.GuestPort = guestPort

	// Parse host part ([hostip:]hostport)
	// Check if there's a colon (indicating host IP is specified)
	colonIdx := strings.LastIndex(hostPart, ":")
	if colonIdx == -1 {
		// No colon found, so hostPart is just the host port
		// Host IP already defaults to 0.0.0.0
		hostPort, err := parsePort(hostPart)
		if err != nil {
			return domain.IngressProxyPort{}, fmt.Errorf("invalid host port: %w", err)
		}
		result.HostPort = hostPort
	} else {
		// Colon found, split into host IP and host port
		hostIP := hostPart[:colonIdx]
		hostPortStr := hostPart[colonIdx+1:]

		// Validate host IP
		if net.ParseIP(hostIP) == nil {
			// Also check if it's a hostname (for localhost, etc.)
			if hostIP != "localhost" {
				return domain.IngressProxyPort{}, fmt.Errorf("invalid host IP: %s", hostIP)
			}
			// Convert localhost to 127.0.0.1
			hostIP = "127.0.0.1"
		}
		result.HostIP = hostIP

		// Parse host port
		hostPort, err := parsePort(hostPortStr)
		if err != nil {
			return domain.IngressProxyPort{}, fmt.Errorf("invalid host port: %w", err)
		}
		result.HostPort = hostPort
	}

	return result, nil
}
