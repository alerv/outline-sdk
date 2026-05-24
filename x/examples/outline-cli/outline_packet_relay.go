// Copyright 2023 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/network/dnsintercept"
	"golang.getoutline.org/sdk/network/dnstruncate"
	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/connectivity"
)

// dnsAssociationTimeout is the idle timeout applied to the DNS leg of the
// intercept relay. DNS queries are one-shot request/response; keeping the
// upstream association alive longer than this just leaks state.
const dnsAssociationTimeout = 5 * time.Second

// defaultAssociationTimeout is the idle timeout for non-DNS UDP associations.
// Long enough to cover typical UDP flows (media, QUIC, etc.) but bounded so
// that a silent/dead remote eventually frees the mapping.
const defaultAssociationTimeout = 5 * time.Minute

type outlinePacketRelay struct {
	packetrelay.DelegatePacketRelay

	remote, fallback packetrelay.PacketRelay
	remotePl         transport.PacketListener
}

func newOutlinePacketRelay(transportConfig, dnsServerIP string) (opr *outlinePacketRelay, err error) {
	opr = &outlinePacketRelay{}

	if opr.remotePl, err = configurl.NewDefaultProviders().NewPacketListener(context.TODO(), transportConfig); err != nil {
		return nil, fmt.Errorf("failed to create UDP packet listener: %w", err)
	}
	baseRemote, err := packetrelay.NewPacketRelayFromPacketListener(opr.remotePl)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP packet relay: %w", err)
	}
	// Both legs of the intercept wrap baseRemote with their own idle timeout
	// so that abandoned upstream associations don't leak listener sockets.
	dnsRelay, err := packetrelay.NewTimeoutPacketRelay(baseRemote, dnsAssociationTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap UDP packet relay with DNS timeout: %w", err)
	}
	defaultRelay, err := packetrelay.NewTimeoutPacketRelay(baseRemote, defaultAssociationTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap UDP packet relay with default timeout: %w", err)
	}
	dnsAddr, err := netip.ParseAddrPort(net.JoinHostPort(dnsServerIP, "53"))
	if err != nil {
		return nil, fmt.Errorf("invalid DNS server address %q: %w", dnsServerIP, err)
	}
	// Route DNS traffic (destined at the configured system resolver) through
	// short-lived associations on dnsRelay; everything else stays on the
	// longer-lived defaultRelay association.
	opr.remote = dnsintercept.NewInterceptDNSPacketRelay(dnsRelay, defaultRelay, dnsAddr, dnsAddr)

	if opr.fallback, err = dnstruncate.NewPacketRelay(); err != nil {
		return nil, fmt.Errorf("failed to create DNS truncate packet relay: %w", err)
	}
	if opr.DelegatePacketRelay, err = packetrelay.NewDelegatePacketRelay(opr.fallback); err != nil {
		return nil, fmt.Errorf("failed to create delegate UDP relay: %w", err)
	}

	return
}

func (relay *outlinePacketRelay) testConnectivityAndRefresh(resolverAddr, domain string) error {
	dialer := transport.PacketListenerDialer{Listener: relay.remotePl}
	dnsResolver := dns.NewUDPResolver(dialer, resolverAddr)
	result, err := connectivity.TestConnectivityWithResolver(context.Background(), dnsResolver, domain)
	if err != nil {
		logging.Info.Printf("connectivity test failed. Refresh skipped. Error: %v\n", err)
		return err
	}
	if result != nil {
		logging.Info.Println("remote server cannot handle UDP traffic, switch to DNS truncate mode.")
		return relay.SetRelay(relay.fallback)
	} else {
		logging.Info.Println("remote server supports UDP, we will delegate all UDP packets to it")
		return relay.SetRelay(relay.remote)
	}
}
