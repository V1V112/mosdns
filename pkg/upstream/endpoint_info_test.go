package upstream

import (
	"reflect"
	"testing"
)

func TestDescribeEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		enableHTTP3 bool
		want        EndpointInfo
	}{
		{
			name: "udp",
			addr: "udp://1.1.1.1",
			want: EndpointInfo{Protocol: "udp", Transport: "udp"},
		},
		{
			name: "udp without scheme",
			addr: "1.1.1.1",
			want: EndpointInfo{Protocol: "udp", Transport: "udp"},
		},
		{
			name: "tcp",
			addr: "tcp://1.1.1.1",
			want: EndpointInfo{Protocol: "tcp", Transport: "tcp", SupportsSocks: true},
		},
		{
			name: "tcp pipeline helper",
			addr: "tcp+pipeline://1.1.1.1",
			want: EndpointInfo{Protocol: "tcp", Transport: "tcp", SupportsSocks: true},
		},
		{
			name: "dot",
			addr: "tls://dns.example",
			want: EndpointInfo{Protocol: "dot", Transport: "tls", SupportsSocks: true},
		},
		{
			name: "dot pipeline helper",
			addr: "tls+pipeline://dns.example",
			want: EndpointInfo{Protocol: "dot", Transport: "tls", SupportsSocks: true},
		},
		{
			name: "doh",
			addr: "https://dns.example/dns-query",
			want: EndpointInfo{Protocol: "doh", Transport: "https", SupportsSocks: true},
		},
		{
			name:        "doh over http3 option",
			addr:        "https://dns.example/dns-query",
			enableHTTP3: true,
			want:        EndpointInfo{Protocol: "doh3", Transport: "quic"},
		},
		{
			name: "doh3 helper",
			addr: "h3://dns.example/dns-query",
			want: EndpointInfo{Protocol: "doh3", Transport: "quic"},
		},
		{
			name: "doq quic scheme",
			addr: "quic://dns.example",
			want: EndpointInfo{Protocol: "doq", Transport: "quic"},
		},
		{
			name: "doq alias",
			addr: "doq://dns.example",
			want: EndpointInfo{Protocol: "doq", Transport: "quic"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DescribeEndpoint(tt.addr, tt.enableHTTP3); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("DescribeEndpoint(%q, %v) = %#v, want %#v", tt.addr, tt.enableHTTP3, got, tt.want)
			}
		})
	}
}
