// Copyright 2026 The Outline Authors
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

package packetrelay

import (
	"net/netip"
	"sync"
)

// lazyPacketRelay is a decorator that defers calling NewAssociation
// on the underlying inner relay until the first SendPacket call.
type lazyPacketRelay struct {
	inner PacketRelay
}

var _ PacketRelay = (*lazyPacketRelay)(nil)

// NewLazyPacketRelay creates a decorator that defers calling NewAssociation
// on the underlying inner relay until the first SendPacket call.
func NewLazyPacketRelay(inner PacketRelay) PacketRelay {
	if inner == nil {
		return nil
	}
	return &lazyPacketRelay{inner: inner}
}

// State machine for the deferred/lazy association initialization:
//
// State             | Description
// ------------------+-----------------------------------------------------------------------
// stateIdle         | Initial state. No association created yet.
// stateInitializing | A SendPacket call is currently invoking NewAssociation on the inner relay.
// stateInitialized  | Inner association has been resolved (either success or error cached).
// stateClosed       | Close() has been called. All resources are cleaned up.
//
// State Transitions:
//
//                    +-----------+
//                    | stateIdle |
//                    +-----------+
//                      /       \
//     SendPacket      /         \ Close()
//   (getAssociation) /           \ (closeAssociation)
//                   v             \
//          +-------------------+   \
//          | stateInitializing |    \
//          +-------------------+     \
//              /           \          v
//  Success or /             \      +-------------+
//  Failure   /       Close() \---->| stateClosed |
//           v    Association       +-------------+
//    +------------------+             ^
//    | stateInitialized |-------------|
//    +------------------+   Close()
//
// State-dependent Behavior for Callers:
//
// 1. SendPacket (calls getAssociation()):
//    - stateIdle: Transitions to stateInitializing, creates the inner association.
//    - stateInitializing: Blocks on cond.Wait() until it transitions to stateInitialized or stateClosed.
//    - stateInitialized: Returns the cached sender/error immediately.
//    - stateClosed: Returns ErrClosed.
//
// 2. ReceivePackets (calls waitReceiver()):
//    - stateIdle: Blocks on cond.Wait() (does NOT trigger initialization).
//    - stateInitializing: Blocks on cond.Wait().
//    - stateInitialized: Returns the cached receiver/error immediately.
//    - stateClosed: Returns ErrClosed.
type relayState int

const (
	stateIdle relayState = iota
	stateInitializing
	stateInitialized
	stateClosed
)

func (r *lazyPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	var mu sync.Mutex
	cond := sync.NewCond(&mu)

	var innerSender PacketSender
	var innerReceiver PacketReceiver
	var initErr error

	var state relayState

	// getAssociation ensures that the inner association is initialized exactly once.
	// If initialization is already in progress, concurrent callers will block until it completes.
	getAssociation := func() (PacketSender, PacketReceiver, error) {
		mu.Lock()
		if state == stateClosed {
			mu.Unlock()
			return nil, nil, ErrClosed
		}
		if state == stateInitialized {
			mu.Unlock()
			return innerSender, innerReceiver, initErr
		}
		if state == stateInitializing {
			for state == stateInitializing {
				cond.Wait()
			}
			if state == stateClosed {
				mu.Unlock()
				return nil, nil, ErrClosed
			}
			mu.Unlock()
			return innerSender, innerReceiver, initErr
		}

		// State is stateIdle. Start initialization.
		state = stateInitializing
		mu.Unlock()

		sender, receiver, err := r.inner.NewAssociation()

		mu.Lock()
		defer mu.Unlock()
		if state == stateClosed {
			if err == nil {
				sender.Close()
			}
			cond.Broadcast()
			return nil, nil, ErrClosed
		}

		state = stateInitialized
		innerSender, innerReceiver, initErr = sender, receiver, err
		cond.Broadcast()
		return innerSender, innerReceiver, initErr
	}

	// closeAssociation closes the inner association if it exists, and aborts any
	// pending or future initializations by unblocking waiting callers with ErrClosed.
	closeAssociation := func() error {
		mu.Lock()
		if state == stateClosed {
			mu.Unlock()
			return ErrClosed
		}
		state = stateClosed
		cond.Broadcast()

		sender := innerSender
		innerSender = nil
		mu.Unlock()

		if sender != nil {
			return sender.Close()
		}
		return nil
	}

	// waitReceiver blocks until the inner association is initialized, or closed.
	waitReceiver := func() (PacketReceiver, error) {
		mu.Lock()
		defer mu.Unlock()
		for state == stateIdle || state == stateInitializing {
			cond.Wait()
		}
		if state == stateClosed {
			return nil, ErrClosed
		}
		return innerReceiver, initErr
	}

	return &lazyPacketSender{getAssociation, closeAssociation}, &lazyPacketReceiver{waitReceiver}, nil
}

type lazyPacketSender struct {
	getAssociation func() (PacketSender, PacketReceiver, error)
	close          func() error
}

var _ PacketSender = (*lazyPacketSender)(nil)

func (s *lazyPacketSender) SendPacket(p []byte, destination netip.AddrPort) error {
	inner, _, err := s.getAssociation()
	if err != nil {
		return err
	}
	return inner.SendPacket(p, destination)
}

func (s *lazyPacketSender) Close() error {
	return s.close()
}

type lazyPacketReceiver struct {
	waitReceiver func() (PacketReceiver, error)
}

var _ PacketReceiver = (*lazyPacketReceiver)(nil)

func (r *lazyPacketReceiver) ReceivePackets(handler PacketHandler) error {
	inner, err := r.waitReceiver()
	if err != nil {
		return err
	}
	return inner.ReceivePackets(handler)
}
