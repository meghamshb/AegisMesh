package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// DNS rebinding was a documented gap through Phase 5.12: the guard resolved a
// hostname to decide whether to allow a request, and the transport then
// resolved it again when dialling. A name that answers with a public address
// on the first lookup and an internal one on the second passed the check and
// was fetched anyway.
//
// These tests use a resolver that deliberately changes its answer between
// calls, which is exactly what an attacker with a low-TTL record controls.

// flipFlopResolver returns `first` on the first lookup and `then` on every
// lookup after that.
type flipFlopResolver struct {
	mu    sync.Mutex
	calls int
	first []net.IPAddr
	then  []net.IPAddr
}

func (r *flipFlopResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return r.first, nil
	}
	return r.then, nil
}

func (r *flipFlopResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func ips(addrs ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out
}

// The core case: public on the check, metadata service on the dial.
func TestDialRefusesRebindToInternalAddress(t *testing.T) {
	resolver := &flipFlopResolver{
		first: ips("93.184.216.34"),   // public: passes IsBlocked
		then:  ips("169.254.169.254"), // internal: must not be dialled
	}
	guard := NewUpstreamGuard().WithResolver(resolver)

	// Pre-flight check passes, as it would for the attacker.
	if blocked, _ := guard.IsBlocked("rebind.example"); blocked {
		t.Fatal("precondition: the first lookup should look benign")
	}

	_, err := guard.DialContext(context.Background(), "tcp", "rebind.example:80")
	if err == nil {
		t.Fatal("dial succeeded against a rebound internal address")
	}

	var blocked ErrBlockedUpstream
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want ErrBlockedUpstream", err)
	}
	if blocked.Reason != "hostname resolves to blocked IP" {
		t.Fatalf("reason = %q", blocked.Reason)
	}
}

// A hostile resolver can return a mix. Picking the acceptable answer out of a
// set that also contains a loopback address is precisely what the attacker is
// counting on, so any blocked address must refuse the whole dial.
func TestDialRefusesWhenAnyResolvedAddressIsInternal(t *testing.T) {
	// A single answer containing both a public and an internal address. The
	// dial path resolves once, so the mix has to be in that one answer.
	guard := NewUpstreamGuard().WithResolver(
		staticResolver{addrs: ips("93.184.216.34", "127.0.0.1")})

	_, err := guard.DialContext(context.Background(), "tcp", "mixed.example:80")
	if err == nil {
		t.Fatal("dial succeeded despite one resolved address being internal")
	}
	var blocked ErrBlockedUpstream
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want ErrBlockedUpstream", err)
	}
}

// The dial must connect to an address it validated, not re-resolve the name.
// If it re-resolved, a third lookup would occur and could return anything.
func TestDialResolvesOnlyOnce(t *testing.T) {
	resolver := &flipFlopResolver{
		first: ips("93.184.216.34"),
		then:  ips("10.0.0.1"),
	}
	guard := NewUpstreamGuard().WithResolver(resolver)

	// Cancelled up front: the dial attempt fails immediately, so the test
	// measures lookups rather than waiting on a real TCP timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = guard.DialContext(ctx, "tcp", "counted.example:80")

	// One lookup inside DialContext. Anything more means the address was
	// resolved again after validation.
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("resolver called %d times during dial, want exactly 1", got)
	}
}

// An IP literal has nothing to rebind: it is checked directly and dialled
// directly, with no lookup at all.
func TestDialWithIPLiteralDoesNotResolve(t *testing.T) {
	resolver := &flipFlopResolver{first: ips("93.184.216.34"), then: ips("127.0.0.1")}
	guard := NewUpstreamGuard().WithResolver(resolver)

	// A blocked literal is refused up front.
	_, err := guard.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	var blocked ErrBlockedUpstream
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want ErrBlockedUpstream for an internal literal", err)
	}
	if resolver.callCount() != 0 {
		t.Fatalf("resolver was consulted %d times for an IP literal", resolver.callCount())
	}
}

// Unresolvable names fail closed at dial time too, matching IsBlocked.
func TestDialFailsClosedOnResolutionFailure(t *testing.T) {
	guard := NewUpstreamGuard().WithResolver(erroringResolver{})

	_, err := guard.DialContext(context.Background(), "tcp", "nowhere.invalid:80")
	var blocked ErrBlockedUpstream
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want ErrBlockedUpstream", err)
	}
	if blocked.Reason != "host could not be resolved" {
		t.Fatalf("reason = %q", blocked.Reason)
	}
}

// A consistently public name must be permitted by the guard - it is an SSRF
// control, not a blanket denial. Asserted by checking the guard did not refuse
// it, rather than by completing a real connection: the point under test is the
// verdict, and reaching out to the internet would make this slow and flaky.
func TestDialPermitsAConsistentlyPublicName(t *testing.T) {
	guard := NewUpstreamGuard().WithResolver(staticResolver{addrs: ips("93.184.216.34")})

	// Cancel immediately so the dial cannot actually leave the machine.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := guard.DialContext(ctx, "tcp", "public.example:80")

	var blocked ErrBlockedUpstream
	if errors.As(err, &blocked) {
		t.Fatalf("guard refused a public destination: %s", blocked.Reason)
	}
	// Some dial error is expected and fine; what matters is that it was not a
	// policy refusal.
	if err == nil {
		t.Log("dial unexpectedly succeeded, which is still not a policy refusal")
	}
}

type erroringResolver struct{}

func (erroringResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("no such host")
}

type staticResolver struct{ addrs []net.IPAddr }

func (s staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return s.addrs, nil
}
