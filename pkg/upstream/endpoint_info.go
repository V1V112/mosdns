package upstream

import "strings"

// EndpointInfo is a display-oriented description of an upstream endpoint.
// Protocol is the logical DNS protocol while Transport is the network/application
// transport visible in the runtime panel.
type EndpointInfo struct {
	Protocol      string
	Transport     string
	SupportsSocks bool
}

// DescribeEndpoint applies the same helper-scheme rules as NewUpstream.
func DescribeEndpoint(addr string, enableHTTP3 bool) EndpointInfo {
	lower := strings.ToLower(strings.TrimSpace(addr))
	scheme := "udp"
	if i := strings.Index(lower, "://"); i >= 0 {
		scheme = lower[:i]
	}

	switch scheme {
	case "tcp", "tcp+pipeline":
		return EndpointInfo{Protocol: "tcp", Transport: "tcp", SupportsSocks: true}
	case "tls", "tls+pipeline":
		return EndpointInfo{Protocol: "dot", Transport: "tls", SupportsSocks: true}
	case "https":
		if enableHTTP3 {
			return EndpointInfo{Protocol: "doh3", Transport: "quic"}
		}
		return EndpointInfo{Protocol: "doh", Transport: "https", SupportsSocks: true}
	case "h3":
		return EndpointInfo{Protocol: "doh3", Transport: "quic"}
	case "quic", "doq":
		return EndpointInfo{Protocol: "doq", Transport: "quic"}
	default:
		return EndpointInfo{Protocol: "udp", Transport: "udp"}
	}
}
