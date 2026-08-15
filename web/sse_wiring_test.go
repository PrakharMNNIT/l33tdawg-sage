package web

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/cfg"
	"golang.org/x/tools/go/packages"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedDashboardEventTypes = []string{
	"remember", "recall", "forget", "vote", "consensus", "agent",
	"import", "update", "governance", "task", "recovery", "access",
	"connectome", "reinstate", "cocommit", "search", "hybrid",
	"pipeline_send", "pipeline_complete", "redeploy",
}

type typedWiringObjects struct {
	broadcastMethod *types.Func
	onEventField    *types.Var
	bridgeFunc      *types.Func
	retrievalHelper *types.Func
	newRestServer   *types.Func
	newDashboard    *types.Func
	dashboardSSE    *types.Var
	sseEventType    types.Type
	sseTypeField    *types.Var
}

type typedEmitSite struct {
	name string
	pos  string
}

type typedWiringScan struct {
	emits            []typedEmitSite
	unresolved       []string
	broadcastEscapes []string
	onEventEscapes   []string
	bridgeCalls      []string
	bridgeSinkCalls  []string
	broadcastCalls   []string
	onEventCalls     []string
	onEventBindings  []string
	retrievalCalls   []string
}

func TestSSEEventWiring(t *testing.T) {
	root := moduleRoot(t)
	pkgs := loadModulePackages(t, root)
	webPkg := requirePackage(t, pkgs, "github.com/l33tdawg/sage/web")
	restPkg := requirePackage(t, pkgs, "github.com/l33tdawg/sage/api/rest")

	eventType := requireNamedType(t, webPkg, "EventType")
	sseEvent := requireNamedType(t, webPkg, "SSEEvent")
	broadcaster := requireNamedType(t, webPkg, "SSEBroadcaster")
	dashboardHandler := requireNamedType(t, webPkg, "DashboardHandler")
	restServer := requireNamedType(t, restPkg, "Server")

	objects := typedWiringObjects{
		broadcastMethod: requireMethod(t, broadcaster, "Broadcast"),
		onEventField:    requireStructField(t, restServer, "OnEvent"),
		bridgeFunc:      requireFunc(t, webPkg, "EventTypeFromREST"),
		retrievalHelper: requireFunc(t, restPkg, "emitContentlessRetrievalActivity"),
		newRestServer:   requireFunc(t, restPkg, "NewServer"),
		newDashboard:    requireFunc(t, webPkg, "NewDashboardHandler"),
		dashboardSSE:    requireStructField(t, dashboardHandler, "SSE"),
		sseEventType:    sseEvent,
		sseTypeField:    requireStructField(t, sseEvent, "Type"),
	}
	scan := scanTypedWiring(root, pkgs, objects)
	registry := eventTypeStrings(AllEventTypes)

	t.Run("intended dashboard vocabulary is exact", func(t *testing.T) {
		require.Len(t, registry, 20)
		assertNoDuplicates(t, registry, "web.AllEventTypes")
		assertSameEventSet(t, expectedDashboardEventTypes, registry,
			"the intended dashboard vocabulary", "web.AllEventTypes", "")
	})

	t.Run("REST bridge preserves every name without remapping", func(t *testing.T) {
		for _, name := range append(append([]string{}, expectedDashboardEventTypes...), "future-event-sentinel") {
			require.Equal(t, EventType(name), EventTypeFromREST(name))
		}
	})

	t.Run("typed EventType constants match the registry", func(t *testing.T) {
		declared := typedEventConstants(t, webPkg, eventType)
		assertNoDuplicates(t, declared, "typed EventType constants")
		assertSameEventSet(t, registry, declared,
			"web.AllEventTypes", "typed EventType constants", "")
	})

	t.Run("actual typed sinks are closed and exact", func(t *testing.T) {
		require.Empty(t, scan.unresolved,
			"dashboard SSE sinks must use direct keyed SSEEvent literals with compile-time constant Type values; unresolved sinks fail closed")
		require.Empty(t, scan.onEventEscapes,
			"the exact api/rest.Server.OnEvent callback must not escape through aliases or unknown wrappers")
		require.Empty(t, scan.broadcastEscapes,
			"the exact SSEBroadcaster.Broadcast method must not escape through aliases or interface dispatch")
		require.NotEmpty(t, scan.broadcastCalls)
		require.NotEmpty(t, scan.onEventCalls)
		require.NotEmpty(t, scan.retrievalCalls)

		emitted := make([]string, 0, len(scan.emits))
		for _, site := range scan.emits {
			emitted = append(emitted, site.name)
		}
		assertSameEventSet(t, registry, emitted,
			"web.AllEventTypes", "events at typed Go sinks", scan.sitesByName())
	})

	t.Run("runtime bridge and helper bypasses stay exact", func(t *testing.T) {
		require.Equal(t, []string{"cmd/sage-gui/node.go"}, scan.bridgeCalls)
		require.Equal(t, []string{"cmd/sage-gui/node.go"}, scan.bridgeSinkCalls,
			"the sole runtime bridge must be the Type expression of the direct dashboard Broadcast literal")
		require.Equal(t, []string{"cmd/sage-gui/node.go"}, scan.onEventBindings,
			"the REST callback must be bound exactly once by the GUI composition root")
		require.Equal(t, []string{"api/rest/memory_handler.go"}, uniqueSorted(scan.retrievalCalls))
	})

	t.Run("route-local protocols never enter the dashboard registry", func(t *testing.T) {
		for _, forbidden := range []string{"wake", "message_wake", "mcp", "wizard", "heartbeat"} {
			require.NotContains(t, registry, forbidden)
		}
		for _, site := range append(append([]string{}, scan.broadcastCalls...), scan.onEventCalls...) {
			require.NotContains(t, site, "api/rest/message_wake.go")
			require.NotContains(t, site, "internal/mcp/")
			require.NotContains(t, site, "wizard")
		}
	})

	t.Run("build-excluded production files cannot hide SSE wiring", func(t *testing.T) {
		require.Empty(t, excludedSSEWiringFiles(t, root, pkgs))
	})
}

func TestTypedSSEWiringGuardRejectsVerifiedBypassMatrix(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "lexical object shadows package constant",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				EventRemember := runtime
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "tuple multi-result declaration shadows package constant",
			body: `func mutate(b *SSEBroadcaster, _ EventType) {
				_, EventRemember := pair()
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "range declaration shadows package constant",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				for _, EventRemember := range []EventType{runtime} {
					b.Broadcast(SSEEvent{Type: EventRemember})
				}
			}`,
		},
		{
			name: "pointer and paren indirection hide overwrite",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				event := &SSEEvent{Type: EventRemember}
				event.Type = runtime
				b.Broadcast(*(event))
			}`,
		},
		{
			name: "inferred value spec is indirect",
			body: `func mutate(b *SSEBroadcaster, _ EventType) {
				var event = SSEEvent{Type: EventRemember}
				b.Broadcast(event)
			}`,
		},
		{
			name: "incremental construction and every overwrite are indirect",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				var event SSEEvent
				event.Type = EventRemember
				event.Type = EventRemember
				event.Type = runtime
				b.Broadcast(event)
			}`,
		},
		{
			name: "helper result argument is unresolved",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				b.Broadcast(makeEvent(runtime))
			}`,
		},
		{
			name: "parameter in direct literal is unresolved",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				b.Broadcast(SSEEvent{Type: runtime})
			}`,
		},
		{
			name: "unused safe literal cannot excuse unresolved sink",
			body: `func mutate(b *SSEBroadcaster, runtime EventType) {
				_ = SSEEvent{Type: EventRemember}
				b.Broadcast(makeEvent(runtime))
			}`,
		},
		{
			name: "literal false branch cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				if false { b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "named constant false branch cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				const disabled = 1 > 0
				if !disabled { b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "constant true else branch cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				if true {} else { b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "constant false loop cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				for false { b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "nonmatching constant switch case cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				switch 1 { case 2: b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "unreachable fallthrough cannot make a later case count",
			body: `func mutate(b *SSEBroadcaster) {
				switch 1 {
				case 1: return; fallthrough
				case 2: b.Broadcast(SSEEvent{Type: EventRemember})
				}
			}`,
		},
		{
			name: "sink after unconditional return cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				return
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "sink after empty infinite loop cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				for true {}
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "unreachable loop break cannot make following emitter reachable",
			body: `func mutate(b *SSEBroadcaster) {
				for true { return; break }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "unselected nested switch break cannot exit outer loop",
			body: `func mutate(b *SSEBroadcaster) {
			outer:
				for true {
					switch 1 { case 2: break outer }
				}
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "constant false nested loop break cannot exit outer loop",
			body: `func mutate(b *SSEBroadcaster) {
			outer:
				for true { for false { break outer } }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "zero length range break cannot exit outer loop",
			body: `func mutate(b *SSEBroadcaster) {
				var zero [0]int
			outer:
				for true { for range zero { break outer } }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "zero integer range break cannot exit outer loop",
			body: `func mutate(b *SSEBroadcaster) {
			outer:
				for true { for range 0 { break outer } }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "empty slice range break cannot exit outer loop",
			body: `func mutate(b *SSEBroadcaster) {
			outer:
				for true { for range []int{} { break outer } }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "sink after empty select cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				select {}
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "mixed return and goto branches skip intervening emitter",
			body: `func mutate(b *SSEBroadcaster, exit bool) {
				if exit { return } else { goto done }
				b.Broadcast(SSEEvent{Type: EventRemember})
			done:
				_ = 1
			}`,
		},
		{
			name: "exhaustive runtime switch returns before emitter",
			body: `func mutate(b *SSEBroadcaster, value int) {
				switch value {
				case 1: return
				default: return
				}
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "parenthesized panic terminates before emitter",
			body: `func mutate(b *SSEBroadcaster) {
				(panic("stop"))
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "parenthesized panic in both branches terminates before join emitter",
			body: `func mutate(b *SSEBroadcaster, cond bool) {
				if cond { (panic("a")) } else { (panic("b")) }
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "closure emitter under constant false outer branch is unreachable",
			body: `func mutate(b *SSEBroadcaster) {
				if false {
					f := func() { b.Broadcast(SSEEvent{Type: EventRemember}) }
					f()
				}
			}`,
		},
		{
			name: "closure emitter constructed after return is unreachable",
			body: `func mutate(b *SSEBroadcaster) {
				return
				_ = func() { b.Broadcast(SSEEvent{Type: EventRemember}) }
			}`,
		},
		{
			name: "closure emitter in constant false short circuit operand is unreachable",
			body: `func mutate(b *SSEBroadcaster) {
				_ = false && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure emitter in constant true or operand is unreachable",
			body: `func mutate(b *SSEBroadcaster) {
				_ = true || func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return false
				}()
			}`,
		},
		{
			name: "closure emitter after nested absorbing false and is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = (false && runtime) && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure emitter after nested absorbing true or is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = (true || runtime) || func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return false
				}()
			}`,
		},
		{
			name: "closure emitter after false outcome equality is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = ((false && runtime) == true) && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure emitter after true outcome false comparison is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = ((true || runtime) == false) && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure emitter after converted false boolean is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = bool(false && runtime) && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure emitter under converted false if condition is unreachable",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				if bool(false && runtime) {
					func() { b.Broadcast(SSEEvent{Type: EventRemember}) }()
				}
			}`,
		},
		{
			name: "named boolean conversion skips closure emitter",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				type flag bool
				_ = flag(false && runtime) && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "generic boolean constrained conversion skips closure emitter",
			body: `func mutate[T interface{ ~bool }](b *SSEBroadcaster, runtime bool) {
				_ = T(false && runtime) && func() T {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return T(true)
				}()
			}`,
		},
		{
			name: "generic exact boolean constraint skips closure emitter",
			body: `func mutate[T interface{ bool }](b *SSEBroadcaster, runtime bool) {
				_ = T(false && runtime) && func() T {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return T(true)
				}()
			}`,
		},
		{
			name: "generic boolean comparable intersection skips closure emitter",
			body: `func mutate[T interface{ ~bool; comparable }](b *SSEBroadcaster, runtime bool) {
				_ = T(false && runtime) && func() T {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return T(true)
				}()
			}`,
		},
		{
			name: "zero value local boolean skips closure emitter",
			body: `func mutate(b *SSEBroadcaster) {
				var dead bool
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "later reassignment cannot erase earlier false fact",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				dead := false
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
				dead = runtime
			}`,
		},
		{
			name: "self assignment preserves local false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				dead = dead
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "forward goto preserves false fact at target",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				goto sink
				dead = true
			sink:
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "exhaustive branch join preserves shared false fact",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				dead := true
				if runtime { dead = false } else { dead = false }
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "sibling branch write cannot erase false fact",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				dead := false
				if runtime {
					dead = true
				} else {
					_ = dead && func() bool {
						b.Broadcast(SSEEvent{Type: EventRemember})
						return true
					}()
				}
			}`,
		},
		{
			name: "constant false branch cannot mutate local false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				if false { dead = true }
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "unselected constant switch case cannot mutate local false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				switch 1 { case 2: dead = true }
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "zero range cannot mutate local false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				for range 0 { dead = true }
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "known single iteration range establishes false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := true
				for range [1]int{} { dead = false }
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "discarded address does not erase local false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_ = &dead
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "empty pointer receiver method does not erase local false fact",
			body: `type flag bool
			func (*flag) observe() {}
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				dead.observe()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "future address escape cannot erase earlier false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
				_ = &dead
			}`,
		},
		{
			name: "future closure capture cannot erase earlier false fact",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
				_ = func() { dead = true }
			}`,
		},
		{
			name: "deferred closure write cannot affect following false sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				defer func() { dead = true }()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "deferred named pointer call cannot affect following false sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := false
				defer setTrue(&dead)
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "parenthesized deferred pointer receiver cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer (dead.setTrue)()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "explicit deferred receiver address cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer (&dead).setTrue()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure stored as deferred argument cannot affect following false sink",
			body: `func run(callback func()) { callback() }
			func mutate(b *SSEBroadcaster) {
				dead := false
				defer run(func() { dead = true })
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure stored by deferred no-op cannot affect following false sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				defer func(func()) {}(func() { dead = true })
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer method stored as deferred argument cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func run(callback func()) { callback() }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer run(dead.setTrue)
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer method stored by deferred no-op cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer func(func()) {}(dead.setTrue)
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer method nested in deferred composite cannot affect following false sink",
			body: `type flag bool
			type holder struct { call func() }
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer func(holder) {}(holder{call: dead.setTrue})
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer method converted in deferred argument cannot affect following false sink",
			body: `type flag bool
			type callback func()
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				defer func(callback) {}(callback(dead.setTrue))
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer alias invoked only by defer cannot affect following false sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := false
				pointer := &dead
				defer setTrue(pointer)
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "closure alias invoked only by defer cannot affect following false sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				callback := func() { dead = true }
				defer callback()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer method alias invoked only by defer cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				callback := dead.setTrue
				defer callback()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "converted pointer method alias invoked only by defer cannot affect following false sink",
			body: `type flag bool
			type callback func()
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				stored := callback(dead.setTrue)
				defer stored()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "composite-held method alias invoked only by defer cannot affect following false sink",
			body: `type flag bool
			type holder struct { call func() }
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				stored := holder{call: dead.setTrue}
				defer stored.call()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "struct field alias assigned before defer cannot affect following false sink",
			body: `type flag bool
			type holder struct { call func() }
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				var stored holder
				stored.call = dead.setTrue
				defer stored.call()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "array element alias assigned before defer cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				var calls [1]func()
				calls[0] = dead.setTrue
				defer calls[0]()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "identity wrapper alias invoked only by defer cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func identity(callback func()) func() { return callback }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				stored := identity(dead.setTrue)
				defer stored()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "append-stored method alias invoked only by defer cannot affect following false sink",
			body: `type flag bool
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				stored := []func(){}
				stored = append(stored, dead.setTrue)
				defer stored[0]()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "aggregate alias construction evaluates synchronous sibling before false sink",
			body: `type holder struct { call func(); ignored bool }
			func mutate(b *SSEBroadcaster) {
				dead := true
				stored := holder{
					call: func() { dead = true },
					ignored: func() bool { dead = false; return true }(),
				}
				defer stored.call()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "identity alias construction evaluates synchronous sibling before false sink",
			body: `func identity(callback func(), _ bool) func() { return callback }
			func mutate(b *SSEBroadcaster) {
				dead := true
				stored := identity(
					func() { dead = true },
					func() bool { dead = false; return true }(),
				)
				defer stored()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "calling unrelated empty aggregate field preserves delayed false source",
			body: `type flag bool
			type holder struct { later func(); now func() }
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				stored := holder{later: dead.setTrue, now: func() {}}
				stored.now()
				defer stored.later()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "len does not invoke callback aliases before false sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				stored := []func(){func() { dead = true }}
				_ = len(stored)
				defer stored[0]()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "delete does not invoke callback aliases before false sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				stored := map[string]func(){"later": func() { dead = true }, "now": func() {}}
				delete(stored, "now")
				defer stored["later"]()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "pointer aggregate alias path fails closed before false sink",
			body: `type holder struct { later func(); now func() }
			func mutate(b *SSEBroadcaster) {
				dead := false
				stored := &holder{later: func() { dead = true }, now: func() {}}
				stored.now()
				defer stored.later()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nested aggregate alias path fails closed before false sink",
			body: `type callbacks struct { later func(); now func() }
			type holder struct { inner callbacks }
			func mutate(b *SSEBroadcaster) {
				dead := false
				stored := holder{inner: callbacks{later: func() { dead = true }, now: func() {}}}
				stored.inner.now()
				defer stored.inner.later()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "dynamic aggregate alias path fails closed before false sink",
			body: `func mutate(b *SSEBroadcaster, index int) {
				dead := false
				stored := [2]func(){func() {}, func() { dead = true }}
				stored[index]()
				defer stored[1]()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "shared slice alias mutation fails closed instead of pruning live sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				other := false
				first := []*bool{&other}
				second := first
				first[0] = &live
				setTrue(second[0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "shared map alias mutation fails closed instead of pruning live sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				other := false
				first := map[int]*bool{0: &other}
				second := first
				first[0] = &live
				setTrue(second[0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "channel alias round trip fails closed instead of pruning live sink",
			body: `func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				channel := make(chan *bool, 1)
				channel <- pointer
				received := <-channel
				*received = true
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nonlocal alias assignment fails closed instead of pruning live sink",
			body: `var globalAlias *bool
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				globalAlias = pointer
				*globalAlias = true
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "later map assignment alias key fails closed",
			body: `func mutateKeys(values map[*bool]struct{}) { for pointer := range values { *pointer = true } }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				values := map[*bool]struct{}{}
				values[pointer] = struct{}{}
				mutateKeys(values)
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "unsupported alias taint propagates through boolean copy",
			body: `type holder struct { later func(); now func() }
			func mutate(b *SSEBroadcaster) {
				dead := false
				stored := &holder{later: func() { dead = true }, now: func() {}}
				stored.now()
				alias := dead
				_ = alias && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "tagless switch case depending on alias taint fails closed",
			body: `type holder struct { later func(); now func() }
			func mutate(b *SSEBroadcaster) {
				dead := false
				stored := &holder{later: func() { dead = true }, now: func() {}}
				stored.now()
				switch {
				case dead:
					b.Broadcast(SSEEvent{Type: EventRemember})
				}
			}`,
		},
		{
			name: "shared append backing mutation fails closed instead of pruning live sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				first := make([]*bool, 0, 1)
				second := first
				first = append(first, &live)
				setTrue(second[:1][0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "identity-wrapped append backing mutation fails closed",
			body: `func identityPointers(values []*bool) []*bool { return values }
			func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				first := make([]*bool, 0, 1)
				second := first
				first = identityPointers(append(first, &live))
				setTrue(second[:1][0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nested append backing mutation fails closed",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				other := false
				first := make([]*bool, 0, 2)
				second := first
				first = append(append(first, &live), &other)
				setTrue(second[:1][0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "synchronously invoked closure append mutation fails closed",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				first := make([]*bool, 0, 1)
				second := first
				first = func() []*bool { return append(first, pointer) }()
				setTrue(second[:1][0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "synchronized goroutine append mutation fails closed",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				first := make([]*bool, 0, 1)
				second := first
				done := make(chan struct{})
				go func() {
					first = append(first, pointer)
					close(done)
				}()
				<-done
				setTrue(second[:1][0])
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "synchronous immediate closure can establish false before sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := true
				func() { dead = false }()
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "synchronous deferred argument closure can establish false before sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := true
				defer func(int) {}(func() int { dead = false; return 0 }())
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "synchronous alias rebind does not mutate old false pointee",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				other := false
				pointer := &dead
				rebind := func() { pointer = &other }
				rebind()
				_ = pointer
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "earlier sibling closure assignment establishes false before sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := true
				_, _ = func() int { dead = false; return 0 }(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "panic in earlier immediate closure prevents later sibling sink",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_, _ = func() int {
					panic("stop")
					dead = true
					return 0
				}(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "deferred builtin panic prevents immediate closure return",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_, _ = func() int {
					defer panic("stop")
					dead = true
					return 0
				}(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nested terminating immediate closure prevents outer return",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_, _ = func() int {
					func() { panic("stop") }()
					dead = true
					return 0
				}(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nested assignment rhs termination prevents outer return",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_, _ = func() int {
					_ = func() int { panic("stop") }()
					dead = true
					return 0
				}(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "nested termination uses sequential outer local facts",
			body: `func mutate(b *SSEBroadcaster) {
				dead := false
				_, _ = func() int {
					run := true
					_ = run && func() bool { panic("stop") }()
					dead = true
					return 0
				}(), dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "immutable local false alias skips closure emitter",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				dead := false && runtime
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "negated immutable local true alias skips closure emitter",
			body: `func mutate(b *SSEBroadcaster, runtime bool) {
				live := true || runtime
				_ = !live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
		},
		{
			name: "sink skipped by forward goto cannot count as an emitter",
			body: `func mutate(b *SSEBroadcaster) {
				goto done
				b.Broadcast(SSEEvent{Type: EventRemember})
			done:
				_ = 1
			}`,
		},
		{
			name: "sink after terminating exhaustive constant switch cannot count",
			body: `func mutate(b *SSEBroadcaster) {
				switch 1 {
				case 1: return
				default: return
				}
				b.Broadcast(SSEEvent{Type: EventRemember})
			}`,
		},
		{
			name: "constant true return blocks later switch fallthrough emitter",
			body: `func mutate(b *SSEBroadcaster) {
				switch 1 {
				case 1: if true { return }; fallthrough
				case 2: b.Broadcast(SSEEvent{Type: EventRemember})
				}
			}`,
		},
		{
			name: "selected switch goto skips following emitter",
			body: `func mutate(b *SSEBroadcaster) {
				switch 1 { case 1: goto done }
				b.Broadcast(SSEEvent{Type: EventRemember})
			done:
				_ = 1
			}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, tc.body)
			require.NotEmpty(t, scan.unresolved,
				"a compile-valid indirect or runtime sink must fail closed")
		})
	}

	t.Run("paren direct literal remains checkable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, _ EventType) {
			b.Broadcast((SSEEvent{Type: EventRemember}))
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("selected constant switch case remains checkable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 { case 1: b.Broadcast(SSEEvent{Type: EventRemember}) }
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("fallthrough into a nonmatching constant case remains reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 {
			case 1: _ = 1; fallthrough
			case 2: b.Broadcast(SSEEvent{Type: EventRemember})
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("intra-case goto can reach fallthrough emitter", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 {
			case 1:
				goto inner
				return
			inner:
				_ = 1
				fallthrough
			case 2:
				b.Broadcast(SSEEvent{Type: EventRemember})
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("goto target remains reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			goto done
		done:
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("break from constant true loop keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			for true { break }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("conditional break from constant true loop keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, exit bool) {
			for true {
				if exit { break }
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("labeled break from nested loop keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, exit bool) {
		outer:
			for true {
				for true {
					if exit { break outer }
				}
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("nonzero range break can exit outer loop", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			var one [1]int
		outer:
			for true { for range one { break outer } }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("positive integer range break can exit outer loop", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
		outer:
			for true { for range 1 { break outer } }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("nonempty slice range break can exit outer loop", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
		outer:
			for true { for range []int{1} { break outer } }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("default select keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			select { default: }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("goto target emitter remains reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, exit bool) {
			if exit { return } else { goto done }
		done:
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("runtime switch fallthrough path keeps emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, value int) {
			switch value {
			case 1: return
			default:
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("runtime boolean switch default keeps emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, value bool) {
			switch value {
			case true: return
			default: b.Broadcast(SSEEvent{Type: EventRemember})
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("parenthesized ordinary call keeps emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			(makeEvent(EventRemember))
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("single conditional parenthesized panic leaves false path reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, cond bool) {
			if cond { (panic("stop")) }
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("invoked closure emitter in reachable outer block remains reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			f := func() { b.Broadcast(SSEEvent{Type: EventRemember}) }
			f()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	for _, tc := range []struct {
		name string
		expr string
	}{
		{name: "constant true and evaluates closure", expr: "true &&"},
		{name: "constant false or evaluates closure", expr: "false ||"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
				_ = `+tc.expr+` func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	t.Run("runtime-capable generic boolean conversion can evaluate closure", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate[T interface{ ~bool }](b *SSEBroadcaster, runtime bool) {
			_ = T(true && runtime) && func() T {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return T(true)
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	for _, constraint := range []string{"bool", "~bool; comparable"} {
		t.Run("runtime generic constraint "+constraint+" can evaluate closure", func(t *testing.T) {
			scan := scanTypedFixture(t, `func mutate[T interface{ `+constraint+` }](b *SSEBroadcaster, runtime bool) {
				_ = T(true && runtime) && func() T {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return T(true)
				}()
			}`)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	t.Run("reassigned local alias remains unknown", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime bool) {
			dead := false && runtime
			dead = runtime
			_ = dead && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("package variable reassigned in another file remains unknown", func(t *testing.T) {
		scan := scanTypedFixtureFiles(t, `
			var dead = false
			func mutate(b *SSEBroadcaster) {
				_ = dead && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`,
			`func enable() { dead = true }`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("pointer receiver method invalidates local boolean fact", func(t *testing.T) {
		scan := scanTypedFixture(t, `
			type flag bool
			func (f *flag) enable() { *f = true }
			func mutate(b *SSEBroadcaster) {
				dead := flag(false)
				dead.enable()
				_ = dead && func() flag {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("write captured by uninvoked closure remains unknown", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			_ = func() { live = false }
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("forward goto skips later write before live fact target", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			goto sink
			live = false
		sink:
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("pointer alias mutation prevents false fact pruning", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := false
			alias := &live
			live = false
			*alias = true
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("simultaneous assignment evaluates all right sides from pre-state", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			left, live := true, false
			left, live = live, left
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("runtime switch paths cannot manufacture a false fact", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, value bool) {
			live := false
			switch value {
			case true: live = false
			default: live = true
			}
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("goto executes later-source pointer mutation before sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := false
			goto later
		sink:
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
			return
		later:
			alias := &live
			*alias = true
			goto sink
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("loop backedge carries invoked closure mutation to later sink visit", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := false
			for iteration := 0; iteration < 2; iteration++ {
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
				func() { live = true }()
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("keyed slice literal is not treated as exactly one iteration", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			for range []int{1: 0} { live = !live }
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("earlier sibling closure assignment establishes true before sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := false
			_, _ = func() int { live = true; return 0 }(), live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("earlier sibling pointer escape keeps sink potentially live", func(t *testing.T) {
		scan := scanTypedFixture(t, `func setTrue(value *bool) int { *value = true; return 0 }
		func mutate(b *SSEBroadcaster) {
			live := false
			_, _ = setTrue(&live), live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("skipped earlier immediate closure cannot mutate live fact", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			_, _ = false && func() bool { live = false; return true }(), live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("terminating literal decision uses state at its expression", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			run := false
			_ = run && func() bool { panic("stop") }()
			run = true
			goto sink
		sink:
			_ = run && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("earlier defer may recover nested panic before later sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			_, _ = func() int {
				defer func() { _ = recover() }()
				func() { panic("stop") }()
				live = false
				return 0
			}(), live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("deferred closure write runs after following live sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := true
			defer func() { live = false }()
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("deferred named pointer write runs after following live sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func setFalse(value *bool) { *value = false }
		func mutate(b *SSEBroadcaster) {
			live := true
			defer setFalse(&live)
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("deferred expression values preserve following live sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `type flag bool
		func (value *flag) setFalse() { *value = false }
		func run(callback func()) { callback() }
		func mutate(b *SSEBroadcaster) {
			live := flag(true)
			defer run(live.setFalse)
			_ = live && func() flag {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("synchronous deferred argument call can establish live sink", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			live := false
			defer func(bool) {}(func() bool { live = true; return live }())
			_ = live && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "synchronous pointer alias call can establish live sink",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				setTrue(pointer)
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "synchronous closure alias call can establish live sink",
			body: `func mutate(b *SSEBroadcaster) {
				live := false
				callback := func() { live = true }
				callback()
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "synchronous converted method alias call can establish live sink",
			body: `type flag bool
			type callback func()
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := flag(false)
				stored := callback(live.setTrue)
				stored()
				_ = live && func() flag { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "synchronous composite alias call can establish live sink",
			body: `type flag bool
			type holder struct { call func() }
			func (value *flag) setTrue() { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := flag(false)
				stored := holder{call: live.setTrue}
				stored.call()
				_ = live && func() flag { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "deferred closure alias write remains after following live sink",
			body: `func mutate(b *SSEBroadcaster) {
				live := true
				callback := func() { live = false }
				defer callback()
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "identity alias evaluates synchronous sibling that establishes live sink",
			body: `func identity(callback func(), _ bool) func() { return callback }
			func mutate(b *SSEBroadcaster) {
				live := false
				stored := identity(
					func() { live = false },
					func() bool { live = true; return true }(),
				)
				defer stored()
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "method alias evaluates synchronous receiver arguments",
			body: `type flag bool
			func (*flag) observe() { _ = 1 }
			func pick(value *flag, _ int) *flag { return value }
			func mutate(b *SSEBroadcaster) {
				live := flag(false)
				observe := pick(&live, func() int { live = true; return 0 }()).observe
				_ = observe
				_ = live && func() flag { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "address alias evaluates synchronous index expression",
			body: `func mutate(b *SSEBroadcaster) {
				live := false
				other := false
				values := []*bool{&other}
				slot := &values[func() int { live = true; return 0 }()]
				_ = slot
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "map literal alias key cannot be false-pruned",
			body: `func mutateKeys(values map[*bool]struct{}) { for pointer := range values { *pointer = true } }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				values := map[*bool]struct{}{pointer: {}}
				mutateKeys(values)
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "known assignment clears propagated alias taint",
			body: `type holder struct { later func(); now func() }
			func mutate(b *SSEBroadcaster) {
				live := false
				stored := &holder{later: func() { live = true }, now: func() {}}
				stored.now()
				alias := live
				alias = true
				_ = alias && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
		{
			name: "synchronized goroutine alias call cannot be false-pruned",
			body: `func setTrue(value *bool) { *value = true }
			func mutate(b *SSEBroadcaster) {
				live := false
				pointer := &live
				done := make(chan struct{})
				go func() { setTrue(pointer); close(done) }()
				<-done
				_ = live && func() bool { b.Broadcast(SSEEvent{Type: EventRemember}); return true }()
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, tc.body)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	for _, tc := range []struct {
		name    string
		initial string
		write   string
	}{
		{name: "goroutine may write false after live sink", initial: "true", write: "false"},
		{name: "goroutine may write true before false sink", initial: "false", write: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
				live := `+tc.initial+`
				go func() { live = `+tc.write+` }()
				_ = live && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	for _, tc := range []struct {
		name       string
		expr       string
		returnType string
	}{
		{name: "runtime-capable bool conversion can evaluate closure", expr: "bool(true && runtime)", returnType: "bool"},
		{name: "definite named boolean conversion evaluates closure", expr: "flag(true || runtime)", returnType: "flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime bool) {
				type flag bool
				_ = `+tc.expr+` && func() `+tc.returnType+` {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	t.Run("runtime-capable nested and can evaluate closure", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime bool) {
			_ = (true && runtime) && func() bool {
				b.Broadcast(SSEEvent{Type: EventRemember})
				return true
			}()
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	for _, tc := range []struct {
		name string
		expr string
	}{
		{name: "false outcome equals false evaluates closure", expr: "((false && runtime) == false)"},
		{name: "symmetric inequality evaluates closure", expr: "(true != (false && runtime))"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime bool) {
				_ = `+tc.expr+` && func() bool {
					b.Broadcast(SSEEvent{Type: EventRemember})
					return true
				}()
			}`)
			require.Empty(t, scan.unresolved)
			require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
		})
	}

	t.Run("selected switch intra-case goto keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 {
			case 1:
				goto inner
			inner:
				_ = 1
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("selected switch break keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 {
			case 1: break
			default: return
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("selected labeled-switch break keeps following emitter reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
		done:
			switch 1 {
			case 1: break done
			default: return
			}
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("fallthrough into a constant switch default remains reachable", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster) {
			switch 1 {
			case 1: fallthrough
			default: b.Broadcast(SSEEvent{Type: EventRemember})
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("compile-time-dead OnEvent call is rejected", func(t *testing.T) {
		scan := scanTypedFixture(t, `func emit(s *Server) {
			if false { s.OnEvent("remember", "", "", "", nil) }
		}`)
		require.NotEmpty(t, scan.unresolved)
		require.Empty(t, scan.emits)
	})

	t.Run("foreign Broadcast decoy cannot impersonate exact method", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, d *decoyBroadcaster, runtime EventType) {
			d.Broadcast(SSEEvent{Type: runtime})
			b.Broadcast(SSEEvent{Type: EventRemember})
		}`)
		require.Empty(t, scan.unresolved)
		require.Equal(t, []typedEmitSite{{name: "remember", pos: "fixture.go:1"}}, normalizeFixtureSites(scan.emits))
	})

	t.Run("exact Broadcast method alias is rejected", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime EventType) {
			emit := b.Broadcast
			emit(SSEEvent{Type: runtime})
		}`)
		require.NotEmpty(t, scan.broadcastEscapes)
	})

	t.Run("interface Broadcast dispatch is rejected", func(t *testing.T) {
		scan := scanTypedFixture(t, `func mutate(b *SSEBroadcaster, runtime EventType) {
			var out interface{ Broadcast(SSEEvent) } = b
			out.Broadcast(SSEEvent{Type: runtime})
		}`)
		require.NotEmpty(t, scan.unresolved)
	})

	t.Run("REST bridge is bound to the exact callback event parameter", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			dashboard := NewDashboardHandler()
			restServer.OnEvent = func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
		}`)
		require.Empty(t, scan.unresolved)
		require.Empty(t, scan.onEventEscapes)
		require.Len(t, scan.bridgeSinkCalls, 1)
		require.Len(t, scan.onEventBindings, 1)
	})

	t.Run("REST bridge rejects a decoy value unrelated to callback parameter", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			dashboard := NewDashboardHandler()
			restServer.OnEvent = func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST("remember")})
			}
		}`)
		require.NotEmpty(t, scan.unresolved)
	})

	t.Run("REST callback rejects indirect assignment", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			dashboard := NewDashboardHandler()
			callback := func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
			restServer.OnEvent = callback
		}`)
		require.NotEmpty(t, scan.onEventEscapes)
	})

	t.Run("later callback overwrite cannot hide behind same-file deduplication", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			dashboard := NewDashboardHandler()
			restServer.OnEvent = func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
			restServer.OnEvent = func(_, _, _, _ string, _ any) {}
		}`)
		require.Empty(t, scan.unresolved)
		require.Empty(t, scan.onEventEscapes)
		require.Len(t, scan.onEventBindings, 2)
		require.NotEqual(t, []string{"fixture.go"}, scan.onEventBindings,
			"the production exact-one assertion must reject a same-file overwrite")
	})

	t.Run("later nil callback overwrite is rejected", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			dashboard := NewDashboardHandler()
			restServer.OnEvent = func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
			restServer.OnEvent = nil
		}`)
		require.NotEmpty(t, scan.onEventEscapes)
	})

	t.Run("decoy REST receiver cannot replace the live constructed server", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			_ = NewServer()
			dashboard := NewDashboardHandler()
			decoy := &Server{}
			decoy.OnEvent = func(eventType, _, _, _ string, _ any) {
				dashboard.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
		}`)
		require.NotEmpty(t, scan.onEventEscapes)
	})

	t.Run("decoy dashboard receiver cannot replace the live constructed dashboard", func(t *testing.T) {
		scan := scanTypedFixture(t, `func wire() {
			restServer := NewServer()
			_ = NewDashboardHandler()
			decoy := &DashboardHandler{SSE: &SSEBroadcaster{}}
			restServer.OnEvent = func(eventType, _, _, _ string, _ any) {
				decoy.SSE.Broadcast(SSEEvent{Type: EventTypeFromREST(eventType)})
			}
		}`)
		require.NotEmpty(t, scan.unresolved)
	})

	t.Run("build-excluded source is rejected before names can impersonate typed sinks", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "hidden.go")
		require.NoError(t, os.WriteFile(path, []byte("//go:build never\npackage hidden\nfunc f(){ sink.Broadcast(event) }\n"), 0o600))
		findings := excludedSSEWiringFiles(t, root, nil)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "hidden.go")
	})
}

func fixturePreamble(body string) string {
	return `package fixture
	type EventType string
	const EventRemember EventType = "remember"
	type SSEEvent struct { Type EventType }
	type SSEBroadcaster struct{}
	func (*SSEBroadcaster) Broadcast(SSEEvent) {}
	type decoyBroadcaster struct{}
	func (*decoyBroadcaster) Broadcast(SSEEvent) {}
	type Server struct { OnEvent func(string, string, string, string, any) }
	type DashboardHandler struct { SSE *SSEBroadcaster }
	func NewServer() *Server { return &Server{} }
	func NewDashboardHandler() *DashboardHandler { return &DashboardHandler{SSE: &SSEBroadcaster{}} }
	func EventTypeFromREST(name string) EventType { return EventType(name) }
	func pair() (int, EventType) { return 0, EventRemember }
	func makeEvent(t EventType) SSEEvent { return SSEEvent{Type: t} }
	` + body
}

func scanTypedFixture(t *testing.T, body string) typedWiringScan {
	return scanTypedFixtureFiles(t, body)
}

func scanTypedFixtureFiles(t *testing.T, bodies ...string) typedWiringScan {
	t.Helper()
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(bodies))
	paths := make([]string, 0, len(bodies))
	for index, body := range bodies {
		path := "fixture.go"
		source := fixturePreamble(body)
		if index > 0 {
			path = fmt.Sprintf("fixture_%d.go", index+1)
			source = "package fixture\n" + body
		}
		file, err := parser.ParseFile(fset, path, source, parser.AllErrors)
		require.NoError(t, err)
		files = append(files, file)
		paths = append(paths, path)
	}
	info := newTypesInfo()
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("fixture", fset, files, info)
	require.NoError(t, err)

	event := requireNamedTypeFromTypes(t, pkg, "SSEEvent")
	broadcaster := requireNamedTypeFromTypes(t, pkg, "SSEBroadcaster")
	server := requireNamedTypeFromTypes(t, pkg, "Server")
	dashboard := requireNamedTypeFromTypes(t, pkg, "DashboardHandler")
	objects := typedWiringObjects{
		broadcastMethod: requireMethod(t, broadcaster, "Broadcast"),
		onEventField:    requireStructField(t, server, "OnEvent"),
		bridgeFunc:      requireFuncFromTypes(t, pkg, "EventTypeFromREST"),
		newRestServer:   requireFuncFromTypes(t, pkg, "NewServer"),
		newDashboard:    requireFuncFromTypes(t, pkg, "NewDashboardHandler"),
		dashboardSSE:    requireStructField(t, dashboard, "SSE"),
		sseEventType:    event,
		sseTypeField:    requireStructField(t, event, "Type"),
	}
	var scan typedWiringScan
	for index, file := range files {
		scanTypedFile("", paths[index], fset, file, info, objects, &scan)
	}
	return scan
}

func normalizeFixtureSites(sites []typedEmitSite) []typedEmitSite {
	out := append([]typedEmitSite(nil), sites...)
	for i := range out {
		if strings.HasPrefix(out[i].pos, "fixture.go:") {
			out[i].pos = "fixture.go:1"
		}
	}
	return out
}

func loadModulePackages(t *testing.T, root string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir: root,
	}
	pkgs, err := packages.Load(cfg, "./...")
	require.NoError(t, err)
	var loadErrors []string
	for _, pkg := range pkgs {
		for _, pkgErr := range pkg.Errors {
			loadErrors = append(loadErrors, pkgErr.Error())
		}
	}
	require.Empty(t, loadErrors, "module packages must type-check before wiring can be audited")
	return pkgs
}

func excludedSSEWiringFiles(t *testing.T, root string, pkgs []*packages.Package) []string {
	t.Helper()
	compiled := map[string]bool{}
	for _, pkg := range pkgs {
		for _, path := range pkg.CompiledGoFiles {
			absolute, err := filepath.Abs(path)
			require.NoError(t, err)
			compiled[filepath.Clean(absolute)] = true
		}
	}
	var findings []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "third_party" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if compiled[filepath.Clean(absolute)] {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SelectorExpr:
				if n.Sel.Name == "Broadcast" || n.Sel.Name == "OnEvent" {
					findings = append(findings, fmt.Sprintf("%s:%d", filepath.ToSlash(path), fset.Position(n.Pos()).Line))
				}
			case *ast.Ident:
				if n.Name == "EventTypeFromREST" {
					findings = append(findings, fmt.Sprintf("%s:%d", filepath.ToSlash(path), fset.Position(n.Pos()).Line))
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	sort.Strings(findings)
	return findings
}

func scanTypedWiring(root string, pkgs []*packages.Package, objects typedWiringObjects) typedWiringScan {
	var scan typedWiringScan
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			path := ""
			if i < len(pkg.CompiledGoFiles) {
				path = pkg.CompiledGoFiles[i]
			}
			scanTypedFile(root, path, pkg.Fset, file, pkg.TypesInfo, objects, &scan)
		}
	}
	sort.Strings(scan.bridgeCalls)
	sort.Strings(scan.bridgeSinkCalls)
	sort.Strings(scan.broadcastCalls)
	sort.Strings(scan.onEventCalls)
	sort.Strings(scan.onEventBindings)
	sort.Strings(scan.retrievalCalls)
	sort.Strings(scan.onEventEscapes)
	sort.Strings(scan.broadcastEscapes)
	sort.Strings(scan.unresolved)
	return scan
}

func scanTypedFile(root, path string, fset *token.FileSet, file *ast.File, info *types.Info, objects typedWiringObjects, scan *typedWiringScan) {
	rel := filepath.ToSlash(path)
	if root != "" {
		if value, err := filepath.Rel(root, path); err == nil {
			rel = filepath.ToSlash(value)
		}
	}
	position := func(pos token.Pos) string {
		p := fset.Position(pos)
		if rel != "" {
			return fmt.Sprintf("%s:%d", rel, p.Line)
		}
		return p.String()
	}
	parents := astParents(file)

	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			called := calledObject(info, n.Fun)
			isDashboardSink := (objects.broadcastMethod != nil && called == objects.broadcastMethod) ||
				(objects.onEventField != nil && called == objects.onEventField) ||
				(objects.retrievalHelper != nil && called == objects.retrievalHelper)
			if isDashboardSink {
				if reason, dead := cfgDeadPath(info, n, parents); dead {
					scan.unresolved = append(scan.unresolved, "dashboard SSE sink is unreachable in function CFG ("+reason+") at "+position(n.Pos()))
					return false
				}
			}
			if isInterfaceBroadcastCall(info, n, objects.sseEventType) {
				scan.unresolved = append(scan.unresolved, "dashboard Broadcast through an interface is forbidden at "+position(n.Pos()))
				return true
			}
			switch {
			case objects.broadcastMethod != nil && called == objects.broadcastMethod:
				pos := position(n.Pos())
				scan.broadcastCalls = append(scan.broadcastCalls, rel)
				names, bridge, err := directBroadcastNames(info, n, parents, objects)
				if err != nil {
					scan.unresolved = append(scan.unresolved, err.Error()+" at "+pos)
					return true
				}
				if bridge {
					scan.bridgeSinkCalls = append(scan.bridgeSinkCalls, rel)
				}
				for _, name := range names {
					scan.emits = append(scan.emits, typedEmitSite{name: name, pos: pos})
				}
			case objects.onEventField != nil && called == objects.onEventField:
				pos := position(n.Pos())
				scan.onEventCalls = append(scan.onEventCalls, rel)
				if len(n.Args) == 0 {
					scan.unresolved = append(scan.unresolved, "OnEvent call without event name at "+pos)
				} else if name, ok := constantString(info, n.Args[0]); ok {
					scan.emits = append(scan.emits, typedEmitSite{name: name, pos: pos})
				} else {
					scan.unresolved = append(scan.unresolved, "OnEvent event name is not compile-time constant at "+pos)
				}
			case objects.retrievalHelper != nil && called == objects.retrievalHelper:
				pos := position(n.Pos())
				scan.retrievalCalls = append(scan.retrievalCalls, rel)
				if len(n.Args) < 2 {
					scan.unresolved = append(scan.unresolved, "contentless retrieval helper lacks event name at "+pos)
				} else if name, ok := constantString(info, n.Args[1]); ok {
					scan.emits = append(scan.emits, typedEmitSite{name: name, pos: pos})
				} else {
					scan.unresolved = append(scan.unresolved, "contentless retrieval event name is not compile-time constant at "+pos)
				}
			}
			if objects.bridgeFunc != nil && called == objects.bridgeFunc {
				scan.bridgeCalls = append(scan.bridgeCalls, rel)
			}
		case *ast.SelectorExpr:
			if objects.broadcastMethod != nil && selectedObject(info, n) == objects.broadcastMethod {
				call, ok := parents[n].(*ast.CallExpr)
				if !ok || unwrapParens(call.Fun) != n {
					scan.broadcastEscapes = append(scan.broadcastEscapes, position(n.Pos()))
				}
				return true
			}
			if objects.onEventField == nil || selectedObject(info, n) != objects.onEventField {
				return true
			}
			if directOnEventBinding(n, parents, info, objects) {
				scan.onEventBindings = append(scan.onEventBindings, rel)
				return true
			}
			if onEventUseIsSanctioned(n, parents, info, objects) {
				return true
			}
			scan.onEventEscapes = append(scan.onEventEscapes, position(n.Pos()))
		}
		return true
	})
}

func cfgDeadPath(info *types.Info, sink ast.Node, parents map[ast.Node]ast.Node) (string, bool) {
	current := sink
	checkedBoundary := false
	for {
		boundary, body := enclosingFunctionBoundary(current, parents)
		facts, tainted, reachesPoint := programPointBooleanFacts(info, body, parents, current.Pos())
		if !reachesPoint {
			return "an earlier expression at the same program point does not return", true
		}
		if reason, dead := shortCircuitDeadPath(info, current, parents, facts); dead {
			return reason, true
		}
		if taintedControlPath(info, current, parents, tainted) {
			return "sink liveness depends on an unsupported local alias effect", true
		}
		if body == nil {
			if checkedBoundary {
				return "", false
			}
			return "sink has no enclosing function body", true
		}
		if reason, dead := cfgBodyDeadPath(info, current, body, parents); dead {
			return reason, true
		}
		checkedBoundary = true
		literal, ok := boundary.(*ast.FuncLit)
		if !ok {
			return "", false
		}
		current = literal
	}
}

func taintedControlPath(info *types.Info, node ast.Node, parents map[ast.Node]ast.Node, tainted map[types.Object]bool) bool {
	referencesTaint := func(expression ast.Expr) bool { return expressionReferencesObjects(info, expression, tainted) }
	for child, parent := node, parents[node]; parent != nil; child, parent = parent, parents[parent] {
		switch current := parent.(type) {
		case *ast.BinaryExpr:
			if (current.Op == token.LAND || current.Op == token.LOR) && current.Y.Pos() <= child.Pos() && child.End() <= current.Y.End() && referencesTaint(current.X) {
				return true
			}
		case *ast.IfStmt:
			if referencesTaint(current.Cond) && current.Cond.End() <= child.Pos() {
				return true
			}
		case *ast.ForStmt:
			if current.Cond != nil && referencesTaint(current.Cond) && current.Body.Pos() <= child.Pos() && child.End() <= current.Body.End() {
				return true
			}
		case *ast.SwitchStmt:
			if current.Tag != nil && referencesTaint(current.Tag) && current.Body.Pos() <= child.Pos() && child.End() <= current.Body.End() {
				return true
			}
		case *ast.CaseClause:
			if len(current.Body) > 0 && current.Body[0].Pos() <= child.Pos() {
				for _, expression := range current.List {
					if referencesTaint(expression) {
						return true
					}
				}
			}
		}
	}
	return false
}

func expressionReferencesObjects(info *types.Info, expression ast.Expr, objects map[types.Object]bool) bool {
	if expression == nil {
		return false
	}
	found := false
	ast.Inspect(expression, func(inner ast.Node) bool {
		ident, ok := inner.(*ast.Ident)
		if ok && objects[info.ObjectOf(ident)] {
			found = true
			return false
		}
		return !found
	})
	return found
}

type booleanFactState struct {
	values  map[types.Object]bool
	escaped map[types.Object]bool
	tainted map[types.Object]bool
	aliases map[types.Object]map[types.Object]bool
	members map[types.Object]map[string]map[types.Object]bool
}

func newBooleanFactState() booleanFactState {
	return booleanFactState{
		values:  map[types.Object]bool{},
		escaped: map[types.Object]bool{},
		tainted: map[types.Object]bool{},
		aliases: map[types.Object]map[types.Object]bool{},
		members: map[types.Object]map[string]map[types.Object]bool{},
	}
}

func programPointBooleanFacts(info *types.Info, body *ast.BlockStmt, parents map[ast.Node]ast.Node, target token.Pos) (map[types.Object]bool, map[types.Object]bool, bool) {
	if body == nil {
		return map[types.Object]bool{}, map[types.Object]bool{}, true
	}
	graph := cfg.New(body, func(call *ast.CallExpr) bool {
		builtin, ok := calledObject(info, call.Fun).(*types.Builtin)
		return !ok || builtin.Name() != "panic"
	})
	if len(graph.Blocks) == 0 {
		return map[types.Object]bool{}, map[types.Object]bool{}, true
	}
	restrictedSwitchCases, selectedSwitchCases, fallthroughSources := staticSwitchFactRestrictions(info, body)
	activePred := map[*cfg.Block]map[*cfg.Block]bool{}
	inState := map[*cfg.Block]booleanFactState{graph.Blocks[0]: newBooleanFactState()}
	outState := map[*cfg.Block]booleanFactState{}
	outTerminates := map[*cfg.Block]bool{}
	queue := []*cfg.Block{graph.Blocks[0]}
	queued := map[*cfg.Block]bool{graph.Blocks[0]: true}
	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		queued[block] = false
		if block != graph.Blocks[0] {
			var incoming booleanFactState
			haveIncoming := false
			for predecessor := range activePred[block] {
				state, ready := outState[predecessor]
				if !ready {
					continue
				}
				if !haveIncoming {
					incoming = cloneBooleanFacts(state)
					haveIncoming = true
				} else {
					incoming = intersectBooleanFacts(incoming, state)
				}
			}
			if !haveIncoming {
				continue
			}
			inState[block] = incoming
		}
		state := cloneBooleanFacts(inState[block])
		blockTerminates := false
		for _, node := range block.Nodes {
			if nodeHasEvaluatedTerminatingLiteral(info, node, parents, state.values) {
				transferBooleanFacts(info, body, parents, node, state)
				blockTerminates = true
				break
			}
			transferBooleanFacts(info, body, parents, node, state)
		}
		if existing, present := outState[block]; present && equalBooleanFacts(existing, state) && outTerminates[block] == blockTerminates {
			continue
		}
		outState[block] = state
		outTerminates[block] = blockTerminates
		if blockTerminates {
			continue
		}
		for _, successor := range booleanFactSuccessors(info, block, parents, state, restrictedSwitchCases, selectedSwitchCases, fallthroughSources) {
			if !successor.Live {
				continue
			}
			if activePred[successor] == nil {
				activePred[successor] = map[*cfg.Block]bool{}
			}
			activePred[successor][block] = true
			if !queued[successor] {
				queue = append(queue, successor)
				queued[successor] = true
			}
		}
	}
	for _, block := range graph.Blocks {
		state, reachable := inState[block]
		if !reachable {
			continue
		}
		state = cloneBooleanFacts(state)
		for _, node := range block.Nodes {
			if node.Pos() <= target && target <= node.End() {
				if !transferBooleanFactsBeforeTarget(info, body, parents, node, target, state) {
					return map[types.Object]bool{}, map[types.Object]bool{}, false
				}
				return cloneBooleanValues(state.values), cloneBooleanValues(state.tainted), true
			}
			transferBooleanFacts(info, body, parents, node, state)
		}
	}
	return map[types.Object]bool{}, map[types.Object]bool{}, false
}

func booleanFactSuccessors(
	info *types.Info,
	block *cfg.Block,
	parents map[ast.Node]ast.Node,
	facts booleanFactState,
	restrictedSwitchCases map[*ast.CaseClause]bool,
	selectedSwitchCases map[*ast.CaseClause]bool,
	fallthroughSources map[*ast.CaseClause]*ast.CaseClause,
) []*cfg.Block {
	successors := block.Succs
	if len(successors) == 1 && successors[0].Kind == cfg.KindRangeLoop {
		loop := successors[0]
		rangeStmt, _ := loop.Stmt.(*ast.RangeStmt)
		if rangeStmtProvablyExactlyOne(info, rangeStmt) && cfgBlockInsideRangeBody(block, rangeStmt) && len(loop.Succs) == 2 {
			return loop.Succs[1:]
		}
	}
	if block.Kind == cfg.KindRangeLoop && rangeStmtProvablyEmpty(info, block.Stmt) && len(successors) == 2 {
		successors = successors[1:]
	} else if block.Kind == cfg.KindRangeLoop {
		rangeStmt, _ := block.Stmt.(*ast.RangeStmt)
		if rangeStmtProvablyExactlyOne(info, rangeStmt) && len(successors) == 2 {
			successors = successors[:1]
		}
	} else if len(successors) == 2 && len(block.Nodes) > 0 {
		condition, ok := block.Nodes[len(block.Nodes)-1].(ast.Expr)
		if ok {
			if _, isSwitchCaseValue := parents[condition].(*ast.CaseClause); !isSwitchCaseValue {
				if value, known := definiteBool(info, condition, facts.values); known {
					if value {
						successors = successors[:1]
					} else {
						successors = successors[1:]
					}
				}
			}
		}
	}
	for _, successor := range successors {
		clause, ok := successor.Stmt.(*ast.CaseClause)
		if ok && successor.Kind == cfg.KindSwitchCaseBody && selectedSwitchCases[clause] {
			return []*cfg.Block{successor}
		}
	}
	filtered := successors[:0]
	for _, successor := range successors {
		clause, ok := successor.Stmt.(*ast.CaseClause)
		if ok && successor.Kind == cfg.KindSwitchCaseBody && restrictedSwitchCases[clause] && !selectedSwitchCases[clause] {
			if !cfgBlockBelongsToClause(block, fallthroughSources[clause]) {
				continue
			}
		}
		filtered = append(filtered, successor)
	}
	return filtered
}

func nodeHasEvaluatedTerminatingLiteral(
	info *types.Info,
	node ast.Node,
	parents map[ast.Node]ast.Node,
	facts map[types.Object]bool,
) bool {
	terminates := false
	ast.Inspect(node, func(inner ast.Node) bool {
		switch current := inner.(type) {
		case *ast.CallExpr:
			switch parents[current].(type) {
			case *ast.DeferStmt, *ast.GoStmt:
				return true
			}
			if builtin, ok := calledObject(info, current.Fun).(*types.Builtin); ok && builtin.Name() == "panic" {
				if expressionEvaluation(info, current, parents, facts) == expressionEvaluated {
					terminates = true
				}
				return false
			}
			literal := directlyCalledLiteralFromCall(current)
			if literal == nil {
				return true
			}
			if expressionEvaluation(info, literal, parents, facts) == expressionEvaluated && straightLineFuncLiteralTerminates(info, parents, literal, facts) {
				terminates = true
			}
			return false
		case *ast.FuncLit:
			return false
		default:
			return true
		}
	})
	return terminates
}

func cfgBlockInsideRangeBody(block *cfg.Block, rangeStmt *ast.RangeStmt) bool {
	if block == nil || rangeStmt == nil || rangeStmt.Body == nil {
		return false
	}
	if block.Stmt != nil && rangeStmt.Body.Pos() <= block.Stmt.Pos() && block.Stmt.End() <= rangeStmt.Body.End() {
		return true
	}
	for _, node := range block.Nodes {
		if rangeStmt.Body.Pos() <= node.Pos() && node.End() <= rangeStmt.Body.End() {
			return true
		}
	}
	return block.Kind == cfg.KindRangeBody && block.Stmt == rangeStmt
}

func rangeStmtProvablyExactlyOne(info *types.Info, rangeStmt *ast.RangeStmt) bool {
	if rangeStmt == nil || rangeStmt.X == nil {
		return false
	}
	valueType := info.TypeOf(unwrapParens(rangeStmt.X))
	if pointer, ok := valueType.Underlying().(*types.Pointer); ok {
		valueType = pointer.Elem()
	}
	if array, ok := valueType.Underlying().(*types.Array); ok {
		return array.Len() == 1
	}
	return false
}

func staticSwitchFactRestrictions(info *types.Info, body *ast.BlockStmt) (
	map[*ast.CaseClause]bool,
	map[*ast.CaseClause]bool,
	map[*ast.CaseClause]*ast.CaseClause,
) {
	restricted := map[*ast.CaseClause]bool{}
	selected := map[*ast.CaseClause]bool{}
	fallthroughSources := map[*ast.CaseClause]*ast.CaseClause{}
	ast.Inspect(body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok && literal.Body != body {
			return false
		}
		switchStmt, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		clauses, selectedIndex, known := selectedConstantSwitchCase(info, switchStmt)
		if !known {
			return true
		}
		for index, clause := range clauses {
			restricted[clause] = true
			if index+1 < len(clauses) && caseClauseEndsWithFallthrough(clause) {
				fallthroughSources[clauses[index+1]] = clause
			}
		}
		if selectedIndex >= 0 {
			selected[clauses[selectedIndex]] = true
		}
		return true
	})
	return restricted, selected, fallthroughSources
}

func caseClauseEndsWithFallthrough(clause *ast.CaseClause) bool {
	if clause == nil || len(clause.Body) == 0 {
		return false
	}
	branch, ok := clause.Body[len(clause.Body)-1].(*ast.BranchStmt)
	return ok && branch.Tok == token.FALLTHROUGH
}

func addressValueIsDirectlyDiscarded(address *ast.UnaryExpr, parents map[ast.Node]ast.Node) bool {
	var expression ast.Expr = address
	for {
		parent := parents[expression]
		paren, ok := parent.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = paren
	}
	assignment, ok := parents[expression].(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != len(assignment.Rhs) {
		return false
	}
	for index, rhs := range assignment.Rhs {
		if rhs != expression {
			continue
		}
		ident, ok := unwrapParens(assignment.Lhs[index]).(*ast.Ident)
		return ok && ident.Name == "_"
	}
	return false
}

func methodBodyIsEmpty(info *types.Info, body *ast.BlockStmt, parents map[ast.Node]ast.Node, method *types.Func) bool {
	var root ast.Node = body
	for parents[root] != nil {
		root = parents[root]
	}
	file, ok := root.(*ast.File)
	if !ok {
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && info.ObjectOf(function.Name) == method {
			return function.Body != nil && len(function.Body.List) == 0
		}
	}
	return false
}

func identityCallArgument(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	call *ast.CallExpr,
) (ast.Expr, bool) {
	function, ok := calledObject(info, call.Fun).(*types.Func)
	if !ok {
		return nil, false
	}
	var root ast.Node = body
	for parents[root] != nil {
		root = parents[root]
	}
	file, ok := root.(*ast.File)
	if !ok {
		return nil, false
	}
	for _, declaration := range file.Decls {
		decl, ok := declaration.(*ast.FuncDecl)
		if !ok || info.ObjectOf(decl.Name) != function || decl.Body == nil || len(decl.Body.List) != 1 {
			continue
		}
		returned, ok := decl.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 1 {
			return nil, false
		}
		ident, ok := unwrapParens(returned.Results[0]).(*ast.Ident)
		if !ok {
			return nil, false
		}
		parameter := info.ObjectOf(ident)
		signature, ok := function.Type().(*types.Signature)
		if !ok {
			return nil, false
		}
		for index := 0; index < signature.Params().Len() && index < len(call.Args); index++ {
			if signature.Params().At(index) == parameter {
				return call.Args[index], true
			}
		}
		return nil, false
	}
	return nil, false
}

func aliasMemberKey(info *types.Info, expression ast.Expr) (types.Object, string, bool) {
	expression = unwrapParens(expression)
	switch current := expression.(type) {
	case *ast.SelectorExpr:
		base, ok := unwrapParens(current.X).(*ast.Ident)
		selection := info.Selections[current]
		field, fieldOK := selectionObject(selection).(*types.Var)
		if !ok || !fieldOK || selection.Kind() == types.MethodVal || selection.Kind() == types.MethodExpr {
			return nil, "", false
		}
		return info.ObjectOf(base), "field:" + field.Name(), true
	case *ast.IndexExpr:
		base, ok := unwrapParens(current.X).(*ast.Ident)
		value := info.Types[unwrapParens(current.Index)].Value
		if !ok || value == nil {
			return nil, "", false
		}
		return info.ObjectOf(base), "index:" + value.ExactString(), true
	default:
		return nil, "", false
	}
}

func booleanAliasSources(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	expression ast.Expr,
	aliases map[types.Object]map[types.Object]bool,
	members map[types.Object]map[string]map[types.Object]bool,
) map[types.Object]bool {
	result := map[types.Object]bool{}
	var collectExpression func(ast.Expr)
	collectAliases := func(object types.Object) {
		if object == nil {
			return
		}
		for source := range aliases[object] {
			result[source] = true
		}
	}
	collectSourceObject := func(object types.Object) {
		if object != nil && booleanOnlyType(object.Type()) {
			result[object] = true
		}
		collectAliases(object)
	}
	collectCapturedWrites := func(literal *ast.FuncLit) {
		ast.Inspect(literal.Body, func(inner ast.Node) bool {
			collectAssignedIdent := func(ident *ast.Ident) {
				object := info.ObjectOf(ident)
				if object != nil && booleanOnlyType(object.Type()) && (object.Pos() < literal.Pos() || object.Pos() > literal.End()) {
					result[object] = true
				}
			}
			switch current := inner.(type) {
			case *ast.AssignStmt:
				for _, lhs := range current.Lhs {
					ident, _ := unwrapParens(lhs).(*ast.Ident)
					if ident != nil {
						collectAssignedIdent(ident)
					} else {
						collectExpression(lhs)
					}
				}
			case *ast.IncDecStmt:
				ident, _ := unwrapParens(current.X).(*ast.Ident)
				collectAssignedIdent(ident)
			case *ast.UnaryExpr:
				if current.Op == token.AND {
					ident, _ := unwrapParens(current.X).(*ast.Ident)
					collectAssignedIdent(ident)
				}
			case *ast.SelectorExpr:
				selection := info.Selections[current]
				method, _ := selectionObject(selection).(*types.Func)
				signature, _ := methodSignature(method)
				if signature != nil && signature.Recv() != nil {
					if _, pointerReceiver := signature.Recv().Type().(*types.Pointer); pointerReceiver && !methodBodyIsEmpty(info, body, parents, method) {
						if ident, ok := unwrapParens(current.X).(*ast.Ident); ok {
							collectSourceObject(info.ObjectOf(ident))
						} else {
							collectExpression(current.X)
						}
					}
				}
			case *ast.CallExpr:
				collectExpression(current.Fun)
				for _, argument := range current.Args {
					collectExpression(argument)
				}
			}
			return true
		})
	}
	collectExpression = func(current ast.Expr) {
		current = unwrapParens(current)
		if object, key, ok := aliasMemberKey(info, current); ok {
			if sources, known := members[object][key]; known {
				for source := range sources {
					result[source] = true
				}
				return
			}
		}
		switch value := current.(type) {
		case *ast.Ident:
			collectAliases(info.ObjectOf(value))
		case *ast.UnaryExpr:
			if value.Op == token.AND {
				if ident, ok := unwrapParens(value.X).(*ast.Ident); ok {
					collectSourceObject(info.ObjectOf(ident))
				} else {
					collectExpression(value.X)
				}
			}
		case *ast.FuncLit:
			collectCapturedWrites(value)
		case *ast.SelectorExpr:
			selection := info.Selections[value]
			method, _ := selectionObject(selection).(*types.Func)
			signature, _ := methodSignature(method)
			if signature != nil && signature.Recv() != nil {
				if _, pointerReceiver := signature.Recv().Type().(*types.Pointer); pointerReceiver && !methodBodyIsEmpty(info, body, parents, method) {
					if ident, ok := unwrapParens(value.X).(*ast.Ident); ok {
						collectSourceObject(info.ObjectOf(ident))
					} else {
						collectExpression(value.X)
					}
					return
				}
			}
			collectExpression(value.X)
		case *ast.CompositeLit:
			for _, element := range value.Elts {
				if keyed, ok := element.(*ast.KeyValueExpr); ok {
					collectExpression(keyed.Key)
					collectExpression(keyed.Value)
					continue
				}
				collectExpression(element)
			}
		case *ast.CallExpr:
			if typeValue, isType := info.Types[value.Fun]; isType && typeValue.IsType() && len(value.Args) == 1 {
				collectExpression(value.Args[0])
			} else if argument, identity := identityCallArgument(info, body, parents, value); identity {
				collectExpression(argument)
			} else if builtin, ok := calledObject(info, value.Fun).(*types.Builtin); ok && builtin.Name() == "append" {
				for _, argument := range value.Args {
					collectExpression(argument)
				}
			}
		case *ast.IndexExpr:
			collectExpression(value.X)
		case *ast.IndexListExpr:
			collectExpression(value.X)
		case *ast.SliceExpr:
			collectExpression(value.X)
		case *ast.TypeAssertExpr:
			collectExpression(value.X)
		case *ast.StarExpr:
			collectExpression(value.X)
		}
	}
	collectExpression(expression)
	return result
}

func markBooleanAliasInertNodes(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	expression ast.Expr,
	aliases map[types.Object]map[types.Object]bool,
	members map[types.Object]map[string]map[types.Object]bool,
	inert map[ast.Node]bool,
) {
	expression = unwrapParens(expression)
	if len(booleanAliasSources(info, body, parents, expression, aliases, members)) == 0 {
		return
	}
	switch current := expression.(type) {
	case *ast.UnaryExpr:
		inert[current] = true
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.FuncLit:
		inert[current] = true
	case *ast.SelectorExpr:
		selection := info.Selections[current]
		method, _ := selectionObject(selection).(*types.Func)
		signature, _ := methodSignature(method)
		if signature != nil && signature.Recv() != nil {
			if _, pointerReceiver := signature.Recv().Type().(*types.Pointer); pointerReceiver {
				inert[current] = true
				markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
				return
			}
		}
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.CompositeLit:
		for _, element := range current.Elts {
			if keyed, ok := element.(*ast.KeyValueExpr); ok {
				markBooleanAliasInertNodes(info, body, parents, keyed.Key, aliases, members, inert)
				markBooleanAliasInertNodes(info, body, parents, keyed.Value, aliases, members, inert)
				continue
			}
			markBooleanAliasInertNodes(info, body, parents, element, aliases, members, inert)
		}
	case *ast.CallExpr:
		if typeValue, isType := info.Types[current.Fun]; isType && typeValue.IsType() && len(current.Args) == 1 {
			markBooleanAliasInertNodes(info, body, parents, current.Args[0], aliases, members, inert)
		} else if argument, identity := identityCallArgument(info, body, parents, current); identity {
			markBooleanAliasInertNodes(info, body, parents, argument, aliases, members, inert)
		} else if builtin, ok := calledObject(info, current.Fun).(*types.Builtin); ok && builtin.Name() == "append" {
			for _, argument := range current.Args {
				markBooleanAliasInertNodes(info, body, parents, argument, aliases, members, inert)
			}
		}
	case *ast.IndexExpr:
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.IndexListExpr:
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.SliceExpr:
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.TypeAssertExpr:
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	case *ast.StarExpr:
		markBooleanAliasInertNodes(info, body, parents, current.X, aliases, members, inert)
	}
}

func booleanAliasMembers(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	expression ast.Expr,
	aliases map[types.Object]map[types.Object]bool,
	members map[types.Object]map[string]map[types.Object]bool,
) (map[string]map[types.Object]bool, bool) {
	expression = unwrapParens(expression)
	if ident, ok := expression.(*ast.Ident); ok {
		stored, known := members[info.ObjectOf(ident)]
		return cloneAliasMembers(stored), known
	}
	literal, ok := expression.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	result := map[string]map[types.Object]bool{}
	for index, element := range literal.Elts {
		key := "index:" + strconv.Itoa(index)
		value := element
		if keyed, keyedOK := element.(*ast.KeyValueExpr); keyedOK {
			value = keyed.Value
			if ident, identKey := unwrapParens(keyed.Key).(*ast.Ident); identKey {
				key = "field:" + ident.Name
			} else if constantValue := info.Types[unwrapParens(keyed.Key)].Value; constantValue != nil {
				key = "index:" + constantValue.ExactString()
			}
		}
		result[key] = booleanAliasSources(info, body, parents, value, aliases, members)
	}
	return result, true
}

func cloneAliasMembers(source map[string]map[types.Object]bool) map[string]map[types.Object]bool {
	if source == nil {
		return nil
	}
	clone := make(map[string]map[types.Object]bool, len(source))
	for key, sources := range source {
		clone[key] = cloneBooleanValues(sources)
	}
	return clone
}

func selectionObject(selection *types.Selection) types.Object {
	if selection == nil {
		return nil
	}
	return selection.Obj()
}

func assignedAliasContainer(info *types.Info, expression ast.Expr) types.Object {
	expression = unwrapParens(expression)
	switch current := expression.(type) {
	case *ast.SelectorExpr:
		return assignedAliasContainer(info, current.X)
	case *ast.IndexExpr:
		return assignedAliasContainer(info, current.X)
	case *ast.IndexListExpr:
		return assignedAliasContainer(info, current.X)
	case *ast.Ident:
		return info.ObjectOf(current)
	default:
		return nil
	}
}

func methodSignature(method *types.Func) (*types.Signature, bool) {
	if method == nil {
		return nil, false
	}
	signature, ok := method.Type().(*types.Signature)
	return signature, ok
}

func aliasExpressionPrecise(info *types.Info, expression ast.Expr, state booleanFactState) bool {
	expression = unwrapParens(expression)
	switch current := expression.(type) {
	case *ast.SelectorExpr:
		if _, method := selectionObject(info.Selections[current]).(*types.Func); method {
			return true
		}
		object, key, ok := aliasMemberKey(info, expression)
		if !ok {
			return false
		}
		_, known := state.members[object][key]
		return known
	case *ast.IndexExpr:
		object, key, ok := aliasMemberKey(info, expression)
		if !ok {
			return false
		}
		_, known := state.members[object][key]
		return known
	case *ast.Ident:
		return true
	default:
		return true
	}
}

func referenceAggregate(object types.Object) bool {
	if object == nil || object.Type() == nil {
		return false
	}
	switch object.Type().Underlying().(type) {
	case *types.Slice, *types.Map:
		return true
	default:
		return false
	}
}

func transferBooleanFacts(info *types.Info, body *ast.BlockStmt, parents map[ast.Node]ast.Node, node ast.Node, state booleanFactState) {
	var markEscaped func(types.Object)
	markEscaped = func(object types.Object) {
		if object == nil {
			return
		}
		if state.escaped[object] {
			return
		}
		state.escaped[object] = true
		for source := range state.aliases[object] {
			markEscaped(source)
		}
		delete(state.aliases, object)
		delete(state.members, object)
		delete(state.values, object)
	}
	markTainted := func(object types.Object) {
		if object == nil {
			return
		}
		state.tainted[object] = true
		delete(state.values, object)
	}
	localAliasVariable := func(ident *ast.Ident) (*types.Var, bool) {
		if ident == nil || ident.Name == "_" {
			return nil, false
		}
		variable, ok := info.ObjectOf(ident).(*types.Var)
		if !ok || (variable.Pkg() != nil && variable.Parent() == variable.Pkg().Scope()) || state.escaped[variable] {
			return nil, false
		}
		return variable, true
	}
	inertAliasNodes := map[ast.Node]bool{}
	aliasUpdates := map[types.Object]map[types.Object]bool{}
	aliasAdditions := map[types.Object]map[types.Object]bool{}
	memberUpdates := map[types.Object]map[string]map[types.Object]bool{}
	memberUpdateKnown := map[types.Object]bool{}
	memberAssignments := map[types.Object]map[string]map[types.Object]bool{}
	recordAlias := func(ident *ast.Ident, expression ast.Expr) bool {
		variable, ok := localAliasVariable(ident)
		if !ok {
			return false
		}
		sources := booleanAliasSources(info, body, parents, expression, state.aliases, state.members)
		if referenceAggregate(variable) {
			ast.Inspect(expression, func(inner ast.Node) bool {
				if literal, closure := inner.(*ast.FuncLit); closure {
					return functionLiteralCallContext(literal, parents) == callSynchronous &&
						expressionEvaluation(info, literal, parents, state.values) != expressionSkipped
				}
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				builtin, builtinOK := calledObject(info, call.Fun).(*types.Builtin)
				if !builtinOK || builtin.Name() != "append" {
					return true
				}
				for _, appended := range call.Args[1:] {
					for source := range booleanAliasSources(info, body, parents, appended, state.aliases, state.members) {
						markTainted(source)
					}
				}
				return true
			})
		}
		aliasUpdates[variable] = sources
		storedMembers, membersKnown := booleanAliasMembers(info, body, parents, expression, state.aliases, state.members)
		memberUpdates[variable] = storedMembers
		memberUpdateKnown[variable] = membersKnown
		if len(sources) > 0 {
			markBooleanAliasInertNodes(info, body, parents, expression, state.aliases, state.members, inertAliasNodes)
		}
		return true
	}
	switch current := node.(type) {
	case *ast.ValueSpec:
		if len(current.Names) == len(current.Values) {
			for index, name := range current.Names {
				recordAlias(name, current.Values[index])
			}
		}
	case *ast.AssignStmt:
		if (current.Tok == token.DEFINE || current.Tok == token.ASSIGN) && len(current.Lhs) == len(current.Rhs) {
			for index, lhs := range current.Lhs {
				ident, _ := unwrapParens(lhs).(*ast.Ident)
				if ident != nil {
					if !recordAlias(ident, current.Rhs[index]) && ident.Name != "_" {
						for source := range booleanAliasSources(info, body, parents, current.Rhs[index], state.aliases, state.members) {
							markTainted(source)
						}
					}
					continue
				}
				container := assignedAliasContainer(info, lhs)
				sources := booleanAliasSources(info, body, parents, current.Rhs[index], state.aliases, state.members)
				if container == nil {
					continue
				}
				if indexed, indexedAssignment := unwrapParens(lhs).(*ast.IndexExpr); indexedAssignment {
					if _, isMap := container.Type().Underlying().(*types.Map); isMap {
						keySources := booleanAliasSources(info, body, parents, indexed.Index, state.aliases, state.members)
						for source := range keySources {
							sources[source] = true
						}
						if len(keySources) > 0 {
							markBooleanAliasInertNodes(info, body, parents, indexed.Index, state.aliases, state.members, inertAliasNodes)
						}
					}
				}
				if len(sources) > 0 {
					if aliasAdditions[container] == nil {
						aliasAdditions[container] = map[types.Object]bool{}
					}
					for source := range sources {
						aliasAdditions[container][source] = true
					}
					markBooleanAliasInertNodes(info, body, parents, current.Rhs[index], state.aliases, state.members, inertAliasNodes)
					if referenceAggregate(container) {
						for source := range sources {
							markTainted(source)
						}
					}
				}
				if memberObject, key, exactMember := aliasMemberKey(info, lhs); exactMember {
					if memberAssignments[memberObject] == nil {
						memberAssignments[memberObject] = map[string]map[types.Object]bool{}
					}
					memberAssignments[memberObject][key] = cloneBooleanValues(sources)
				}
			}
		}
	}
	markCapturedWrites := func(literal *ast.FuncLit) {
		ast.Inspect(literal.Body, func(inner ast.Node) bool {
			markIdent := func(ident *ast.Ident) {
				object := info.ObjectOf(ident)
				if object != nil && (object.Pos() < literal.Pos() || object.Pos() > literal.End()) {
					markEscaped(object)
				}
			}
			switch current := inner.(type) {
			case *ast.AssignStmt:
				for _, lhs := range current.Lhs {
					ident, _ := unwrapParens(lhs).(*ast.Ident)
					markIdent(ident)
				}
			case *ast.IncDecStmt:
				ident, _ := unwrapParens(current.X).(*ast.Ident)
				markIdent(ident)
			case *ast.RangeStmt:
				for _, expression := range []ast.Expr{current.Key, current.Value} {
					ident, _ := unwrapParens(expression).(*ast.Ident)
					markIdent(ident)
				}
			case *ast.UnaryExpr:
				if current.Op == token.AND && !addressValueIsDirectlyDiscarded(current, parents) {
					ident, _ := unwrapParens(current.X).(*ast.Ident)
					markIdent(ident)
				}
			case *ast.SelectorExpr:
				selection := info.Selections[current]
				if selection == nil {
					break
				}
				method, ok := selection.Obj().(*types.Func)
				if !ok {
					break
				}
				signature, ok := method.Type().(*types.Signature)
				if !ok || signature.Recv() == nil {
					break
				}
				if _, ok := signature.Recv().Type().(*types.Pointer); ok && !methodBodyIsEmpty(info, body, parents, method) {
					ident, _ := unwrapParens(current.X).(*ast.Ident)
					markIdent(ident)
				}
			case *ast.CallExpr:
				for source := range booleanAliasSources(info, body, parents, current.Fun, state.aliases, state.members) {
					markEscaped(source)
				}
				for _, argument := range current.Args {
					for source := range booleanAliasSources(info, body, parents, argument, state.aliases, state.members) {
						markEscaped(source)
					}
				}
			}
			return true
		})
	}
	ast.Inspect(node, func(inner ast.Node) bool {
		switch current := inner.(type) {
		case *ast.AssignStmt:
			for _, lhs := range current.Lhs {
				if _, direct := unwrapParens(lhs).(*ast.Ident); direct {
					continue
				}
				containsIndirectWrite := false
				ast.Inspect(lhs, func(node ast.Node) bool {
					if _, indirect := node.(*ast.StarExpr); indirect {
						containsIndirectWrite = true
					}
					return true
				})
				if !containsIndirectWrite {
					continue
				}
				for source := range booleanAliasSources(info, body, parents, lhs, state.aliases, state.members) {
					markEscaped(source)
				}
			}
			return true
		case *ast.IncDecStmt:
			for source := range booleanAliasSources(info, body, parents, current.X, state.aliases, state.members) {
				markEscaped(source)
			}
			return true
		case *ast.SendStmt:
			for source := range booleanAliasSources(info, body, parents, current.Value, state.aliases, state.members) {
				markTainted(source)
			}
			return true
		case *ast.CallExpr:
			if typeValue, isType := info.Types[current.Fun]; isType && typeValue.IsType() {
				return true
			}
			if _, identity := identityCallArgument(info, body, parents, current); identity {
				return true
			}
			if builtin, ok := calledObject(info, current.Fun).(*types.Builtin); ok {
				switch builtin.Name() {
				case "append", "cap", "clear", "delete", "len":
					return true
				}
			}
			if _, deferred := parents[current].(*ast.DeferStmt); deferred {
				return true
			}
			if directlyCalledLiteralFromCall(current) == nil {
				for source := range booleanAliasSources(info, body, parents, current.Fun, state.aliases, state.members) {
					if aliasExpressionPrecise(info, current.Fun, state) {
						markEscaped(source)
					} else {
						markTainted(source)
					}
				}
			}
			for _, argument := range current.Args {
				for source := range booleanAliasSources(info, body, parents, argument, state.aliases, state.members) {
					if aliasExpressionPrecise(info, argument, state) {
						markEscaped(source)
					} else {
						markTainted(source)
					}
				}
			}
			return true
		case *ast.FuncLit:
			if inertAliasNodes[current] {
				return false
			}
			switch functionLiteralCallContext(current, parents) {
			case callDeferred:
				return false
			case callGoroutine:
				ast.Inspect(current.Body, func(inner ast.Node) bool {
					if nested, closure := inner.(*ast.FuncLit); closure {
						return functionLiteralCallContext(nested, parents) == callSynchronous &&
							expressionEvaluation(info, nested, parents, state.values) != expressionSkipped
					}
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					builtin, builtinOK := calledObject(info, call.Fun).(*types.Builtin)
					if !builtinOK || builtin.Name() != "append" {
						return true
					}
					for _, appended := range call.Args[1:] {
						for source := range booleanAliasSources(info, body, parents, appended, state.aliases, state.members) {
							markTainted(source)
						}
					}
					return true
				})
			case callSynchronous:
				switch expressionEvaluation(info, current, parents, state.values) {
				case expressionSkipped:
					return false
				case expressionEvaluated:
					if supported, _ := transferStraightLineFuncLiteral(info, body, parents, current, state); supported {
						return false
					}
				}
			}
			if expressionIsOnlyDeferredOperand(info, current, parents) {
				return false
			}
			markCapturedWrites(current)
			return false
		case *ast.UnaryExpr:
			if inertAliasNodes[current] {
				return true
			}
			if current.Op == token.AND && !addressValueIsDirectlyDiscarded(current, parents) && !expressionIsOnlyDeferredOperand(info, current, parents) {
				ident, _ := unwrapParens(current.X).(*ast.Ident)
				markEscaped(info.ObjectOf(ident))
			}
		case *ast.SelectorExpr:
			if inertAliasNodes[current] {
				return true
			}
			selection := info.Selections[current]
			if selection == nil {
				break
			}
			method, ok := selection.Obj().(*types.Func)
			if !ok {
				break
			}
			signature, ok := method.Type().(*types.Signature)
			if !ok || signature.Recv() == nil {
				break
			}
			if _, ok := signature.Recv().Type().(*types.Pointer); ok && !expressionIsOnlyDeferredOperand(info, current, parents) && !methodBodyIsEmpty(info, body, parents, method) {
				ident, _ := unwrapParens(current.X).(*ast.Ident)
				markEscaped(info.ObjectOf(ident))
			}
		case *ast.Ident:
			rangeStmt, ok := parents[current].(*ast.RangeStmt)
			if ok && (rangeStmt.Key == current || rangeStmt.Value == current) {
				markEscaped(info.ObjectOf(current))
			}
		}
		return true
	})
	localVar := func(ident *ast.Ident) (*types.Var, bool) {
		if ident == nil || ident.Name == "_" {
			return nil, false
		}
		variable, ok := info.ObjectOf(ident).(*types.Var)
		if !ok || (variable.Pkg() != nil && variable.Parent() == variable.Pkg().Scope()) || state.escaped[variable] {
			return nil, false
		}
		return variable, true
	}
	set := func(variable *types.Var, expr ast.Expr, source booleanFactState) {
		if variable == nil {
			return
		}
		if value, known := definiteBool(info, expr, source.values); known {
			state.values[variable] = value
			delete(state.tainted, variable)
		} else if expressionReferencesObjects(info, expr, source.tainted) {
			delete(state.values, variable)
			state.tainted[variable] = true
		} else {
			delete(state.values, variable)
		}
	}
	switch current := node.(type) {
	case *ast.ValueSpec:
		before := cloneBooleanFacts(state)
		for index, name := range current.Names {
			variable, ok := localVar(name)
			if !ok {
				continue
			}
			if len(current.Names) == len(current.Values) {
				set(variable, current.Values[index], before)
			} else if len(current.Values) == 0 && booleanOnlyType(variable.Type()) {
				state.values[variable] = false
			} else {
				delete(state.values, variable)
			}
		}
	case *ast.AssignStmt:
		before := cloneBooleanFacts(state)
		updates := map[*types.Var]ast.Expr{}
		for index, lhs := range current.Lhs {
			ident, _ := unwrapParens(lhs).(*ast.Ident)
			variable, ok := localVar(ident)
			if !ok {
				continue
			}
			if (current.Tok == token.DEFINE || current.Tok == token.ASSIGN) && len(current.Lhs) == len(current.Rhs) {
				updates[variable] = current.Rhs[index]
			} else {
				updates[variable] = nil
			}
		}
		for variable, expr := range updates {
			set(variable, expr, before)
		}
	case *ast.IncDecStmt:
		ident, _ := unwrapParens(current.X).(*ast.Ident)
		if variable, ok := localVar(ident); ok {
			delete(state.values, variable)
		}
	}
	for variable, sources := range aliasUpdates {
		if len(sources) == 0 {
			delete(state.aliases, variable)
			continue
		}
		state.aliases[variable] = cloneBooleanValues(sources)
	}
	for variable, known := range memberUpdateKnown {
		if !known {
			delete(state.members, variable)
			continue
		}
		state.members[variable] = cloneAliasMembers(memberUpdates[variable])
	}
	for variable, sources := range aliasAdditions {
		if state.aliases[variable] == nil {
			state.aliases[variable] = map[types.Object]bool{}
		}
		for source := range sources {
			state.aliases[variable][source] = true
		}
	}
	for variable, assignments := range memberAssignments {
		if state.members[variable] == nil {
			state.members[variable] = map[string]map[types.Object]bool{}
		}
		for key, sources := range assignments {
			state.members[variable][key] = cloneBooleanValues(sources)
		}
	}
}

func transferBooleanFactsBeforeTarget(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	node ast.Node,
	target token.Pos,
	state booleanFactState,
) bool {
	reachesTarget := true
	ast.Inspect(node, func(inner ast.Node) bool {
		if inner == nil || inner == node {
			return true
		}
		if inner.Pos() >= target {
			return false
		}
		if inner.End() >= target {
			return true
		}
		switch current := inner.(type) {
		case *ast.CallExpr:
			if literal := directlyCalledLiteralFromCall(current); literal != nil {
				context := functionLiteralCallContext(literal, parents)
				if context == callDeferred || context == callGoroutine {
					transferBooleanFacts(info, body, parents, current, state)
					return false
				}
				status := expressionEvaluation(info, literal, parents, state.values)
				if status == expressionSkipped {
					return false
				}
				if status == expressionEvaluated {
					initialFacts := cloneBooleanValues(state.values)
					if supported, returns := transferStraightLineFuncLiteral(info, body, parents, literal, state); supported {
						if !returns {
							reachesTarget = false
						}
						return false
					}
					if straightLineFuncLiteralTerminates(info, parents, literal, initialFacts) {
						reachesTarget = false
					}
				}
				transferBooleanFacts(info, body, parents, current, state)
				return false
			}
			transferBooleanFacts(info, body, parents, current, state)
			return false
		case *ast.FuncLit:
			if expressionEvaluation(info, current, parents, state.values) != expressionSkipped {
				transferBooleanFacts(info, body, parents, current, state)
			}
			return false
		case *ast.UnaryExpr:
			if current.Op == token.AND {
				transferBooleanFacts(info, body, parents, current, state)
				return false
			}
		case *ast.SelectorExpr:
			selection := info.Selections[current]
			if selection != nil {
				if method, ok := selection.Obj().(*types.Func); ok {
					if signature, ok := method.Type().(*types.Signature); ok && signature.Recv() != nil {
						if _, ok := signature.Recv().Type().(*types.Pointer); ok {
							transferBooleanFacts(info, body, parents, current, state)
							return false
						}
					}
				}
			}
		}
		return true
	})
	return reachesTarget
}

type expressionEvaluationStatus uint8

const (
	expressionEvaluated expressionEvaluationStatus = iota
	expressionSkipped
	expressionMaybeEvaluated
)

func expressionEvaluation(
	info *types.Info,
	node ast.Node,
	parents map[ast.Node]ast.Node,
	facts map[types.Object]bool,
) expressionEvaluationStatus {
	status := expressionEvaluated
	for child, parent := node, parents[node]; parent != nil; child, parent = parent, parents[parent] {
		switch ancestor := parent.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return status
		case *ast.BinaryExpr:
			if ancestor.Y != child || (ancestor.Op != token.LAND && ancestor.Op != token.LOR) {
				continue
			}
			left, known := definiteBool(info, ancestor.X, facts)
			if known {
				if (ancestor.Op == token.LAND && !left) || (ancestor.Op == token.LOR && left) {
					return expressionSkipped
				}
				continue
			}
			status = expressionMaybeEvaluated
		}
	}
	return status
}

type directCallContext uint8

const (
	callNotDirect directCallContext = iota
	callSynchronous
	callDeferred
	callGoroutine
)

func functionLiteralCallContext(literal *ast.FuncLit, parents map[ast.Node]ast.Node) directCallContext {
	var expression ast.Expr = literal
	for {
		parent, ok := parents[expression].(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parent
	}
	call, ok := parents[expression].(*ast.CallExpr)
	if !ok || unwrapParens(call.Fun) != literal {
		return callNotDirect
	}
	switch parents[call].(type) {
	case *ast.DeferStmt:
		return callDeferred
	case *ast.GoStmt:
		return callGoroutine
	default:
		return callSynchronous
	}
}

func expressionIsOnlyDeferredOperand(info *types.Info, expression ast.Expr, parents map[ast.Node]ast.Node) bool {
	for parent := parents[ast.Node(expression)]; parent != nil; parent = parents[parent] {
		call, ok := parent.(*ast.CallExpr)
		if !ok {
			continue
		}
		if typeValue, isType := info.Types[call.Fun]; isType && typeValue.IsType() && len(call.Args) == 1 {
			continue
		}
		if _, deferred := parents[call].(*ast.DeferStmt); deferred {
			return true
		}
		return false
	}
	return false
}

func directlyCalledLiteralFromCall(call *ast.CallExpr) *ast.FuncLit {
	if call == nil {
		return nil
	}
	literal, _ := unwrapParens(call.Fun).(*ast.FuncLit)
	return literal
}

func transferStraightLineFuncLiteral(
	info *types.Info,
	body *ast.BlockStmt,
	parents map[ast.Node]ast.Node,
	literal *ast.FuncLit,
	state booleanFactState,
) (bool, bool) {
	for index, statement := range literal.Body.List {
		switch statement.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.EmptyStmt:
		case *ast.ReturnStmt:
			if index != len(literal.Body.List)-1 {
				return false, true
			}
		default:
			return false, true
		}
	}
	for _, statement := range literal.Body.List {
		if nodeHasEvaluatedTerminatingLiteral(info, statement, parents, state.values) {
			transferBooleanFacts(info, body, parents, statement, state)
			return true, false
		}
		transferBooleanFacts(info, body, parents, statement, state)
	}
	return true, true
}

func straightLineFuncLiteralTerminates(
	info *types.Info,
	parents map[ast.Node]ast.Node,
	literal *ast.FuncLit,
	initialFacts map[types.Object]bool,
) bool {
	priorDeferredCall := false
	deferredBuiltinPanic := false
	state := newBooleanFactState()
	state.values = cloneBooleanValues(initialFacts)
	for index, statement := range literal.Body.List {
		if _, isDefer := statement.(*ast.DeferStmt); !isDefer && nodeHasEvaluatedTerminatingLiteral(info, statement, parents, state.values) {
			return !priorDeferredCall
		}
		switch current := statement.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.DeclStmt, *ast.EmptyStmt:
		case *ast.ExprStmt:
			call, ok := unwrapParens(current.X).(*ast.CallExpr)
			if ok && callDefinitelyTerminates(info, parents, call, state.values) {
				return !priorDeferredCall
			}
		case *ast.ReturnStmt:
			return deferredBuiltinPanic
		case *ast.DeferStmt:
			if callDefinitelyTerminates(info, parents, current.Call, state.values) && !priorDeferredCall {
				deferredBuiltinPanic = true
			} else {
				priorDeferredCall = true
			}
		default:
			return false
		}
		if index == len(literal.Body.List)-1 {
			return deferredBuiltinPanic
		}
		transferBooleanFacts(info, literal.Body, parents, statement, state)
	}
	return deferredBuiltinPanic
}

func callDefinitelyTerminates(
	info *types.Info,
	parents map[ast.Node]ast.Node,
	call *ast.CallExpr,
	facts map[types.Object]bool,
) bool {
	if call == nil {
		return false
	}
	if builtin, ok := calledObject(info, call.Fun).(*types.Builtin); ok && builtin.Name() == "panic" {
		return true
	}
	literal := directlyCalledLiteralFromCall(call)
	return literal != nil && straightLineFuncLiteralTerminates(info, parents, literal, facts)
}

func cloneBooleanFacts(source booleanFactState) booleanFactState {
	return booleanFactState{
		values:  cloneBooleanValues(source.values),
		escaped: cloneBooleanValues(source.escaped),
		tainted: cloneBooleanValues(source.tainted),
		aliases: cloneBooleanAliases(source.aliases),
		members: cloneBooleanMembers(source.members),
	}
}

func intersectBooleanFacts(left, right booleanFactState) booleanFactState {
	result := cloneBooleanFacts(left)
	for object, value := range result.values {
		if other, present := right.values[object]; !present || other != value {
			delete(result.values, object)
		}
	}
	for object := range right.escaped {
		result.escaped[object] = true
	}
	for object := range right.tainted {
		result.tainted[object] = true
	}
	for object, sources := range right.aliases {
		if result.aliases[object] == nil {
			result.aliases[object] = map[types.Object]bool{}
		}
		for source := range sources {
			result.aliases[object][source] = true
		}
	}
	for object := range result.escaped {
		delete(result.values, object)
		delete(result.aliases, object)
		delete(result.members, object)
	}
	for object := range result.tainted {
		delete(result.values, object)
	}
	for object, storedMembers := range result.members {
		otherMembers, present := right.members[object]
		if !present {
			delete(result.members, object)
			continue
		}
		for key, sources := range storedMembers {
			if !equalBooleanValues(sources, otherMembers[key]) {
				delete(storedMembers, key)
			}
		}
	}
	return result
}

func equalBooleanFacts(left, right booleanFactState) bool {
	return equalBooleanValues(left.values, right.values) &&
		equalBooleanValues(left.escaped, right.escaped) &&
		equalBooleanValues(left.tainted, right.tainted) &&
		equalBooleanAliases(left.aliases, right.aliases) &&
		equalBooleanMembers(left.members, right.members)
}

func cloneBooleanAliases(source map[types.Object]map[types.Object]bool) map[types.Object]map[types.Object]bool {
	clone := make(map[types.Object]map[types.Object]bool, len(source))
	for object, sources := range source {
		clone[object] = cloneBooleanValues(sources)
	}
	return clone
}

func equalBooleanAliases(left, right map[types.Object]map[types.Object]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for object, sources := range left {
		if !equalBooleanValues(sources, right[object]) {
			return false
		}
	}
	return true
}

func cloneBooleanMembers(source map[types.Object]map[string]map[types.Object]bool) map[types.Object]map[string]map[types.Object]bool {
	clone := make(map[types.Object]map[string]map[types.Object]bool, len(source))
	for object, members := range source {
		clone[object] = cloneAliasMembers(members)
	}
	return clone
}

func equalBooleanMembers(left, right map[types.Object]map[string]map[types.Object]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for object, leftMembers := range left {
		rightMembers, present := right[object]
		if !present || len(leftMembers) != len(rightMembers) {
			return false
		}
		for key, sources := range leftMembers {
			if !equalBooleanValues(sources, rightMembers[key]) {
				return false
			}
		}
	}
	return true
}

func cloneBooleanValues(source map[types.Object]bool) map[types.Object]bool {
	clone := make(map[types.Object]bool, len(source))
	for object, value := range source {
		clone[object] = value
	}
	return clone
}

func equalBooleanValues(left, right map[types.Object]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for object, value := range left {
		if other, present := right[object]; !present || other != value {
			return false
		}
	}
	return true
}

func shortCircuitDeadPath(info *types.Info, node ast.Node, parents map[ast.Node]ast.Node, facts map[types.Object]bool) (string, bool) {
	for child, parent := node, parents[node]; parent != nil; child, parent = parent, parents[parent] {
		switch ancestor := parent.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return "", false
		case *ast.BinaryExpr:
			if ancestor.Y != child {
				continue
			}
			left, known := definiteBool(info, ancestor.X, facts)
			if !known {
				continue
			}
			if ancestor.Op == token.LAND && !left {
				return "constant-false && left operand skips closure construction", true
			}
			if ancestor.Op == token.LOR && left {
				return "constant-true || left operand skips closure construction", true
			}
		}
	}
	return "", false
}

func enclosingFunctionBoundary(node ast.Node, parents map[ast.Node]ast.Node) (ast.Node, *ast.BlockStmt) {
	for node = parents[node]; node != nil; node = parents[node] {
		switch function := node.(type) {
		case *ast.FuncDecl:
			return function, function.Body
		case *ast.FuncLit:
			return function, function.Body
		}
	}
	return nil, nil
}

func cfgBodyDeadPath(info *types.Info, sink ast.Node, body *ast.BlockStmt, parents map[ast.Node]ast.Node) (string, bool) {
	graph := cfg.New(body, func(call *ast.CallExpr) bool {
		builtin, ok := calledObject(info, call.Fun).(*types.Builtin)
		return !ok || builtin.Name() != "panic"
	})
	if len(graph.Blocks) == 0 {
		return "function CFG has no entry block", true
	}
	restrictedSwitchCases := map[*ast.CaseClause]bool{}
	selectedSwitchCases := map[*ast.CaseClause]bool{}
	fallthroughSources := map[*ast.CaseClause]*ast.CaseClause{}
	ast.Inspect(body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok && literal.Body != body {
			return false
		}
		switchStmt, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		clauses, selectedIndex, known := selectedConstantSwitchCase(info, switchStmt)
		if !known {
			return true
		}
		for _, clause := range clauses {
			restrictedSwitchCases[clause] = true
		}
		for index := 0; index+1 < len(clauses); index++ {
			clauseBody := clauses[index].Body
			if len(clauseBody) == 0 {
				continue
			}
			branch, ok := clauseBody[len(clauseBody)-1].(*ast.BranchStmt)
			if ok && branch.Tok == token.FALLTHROUGH {
				fallthroughSources[clauses[index+1]] = clauses[index]
			}
		}
		if selectedIndex >= 0 {
			selectedSwitchCases[clauses[selectedIndex]] = true
		}
		return true
	})
	reachable := map[*cfg.Block]bool{}
	queue := []*cfg.Block{graph.Blocks[0]}
	for len(queue) > 0 {
		block := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reachable[block] {
			continue
		}
		reachable[block] = true
		successors := block.Succs
		if parenthesizedBuiltinPanicIndex(info, block) >= 0 {
			successors = nil
		} else if block.Kind == cfg.KindRangeLoop && rangeStmtProvablyEmpty(info, block.Stmt) && len(successors) == 2 {
			successors = successors[1:]
		} else if len(successors) == 2 && len(block.Nodes) > 0 {
			if condition, ok := block.Nodes[len(block.Nodes)-1].(ast.Expr); ok {
				_, isSwitchCaseValue := parents[condition].(*ast.CaseClause)
				facts, _, _ := programPointBooleanFacts(info, body, parents, condition.Pos())
				if value, known := definiteBool(info, condition, facts); known && !isSwitchCaseValue {
					if value {
						successors = successors[:1]
					} else {
						successors = successors[1:]
					}
				}
			}
		}
		selectedSuccessor := (*cfg.Block)(nil)
		for _, successor := range successors {
			if clause, ok := successor.Stmt.(*ast.CaseClause); ok && successor.Kind == cfg.KindSwitchCaseBody && selectedSwitchCases[clause] {
				selectedSuccessor = successor
				break
			}
		}
		if selectedSuccessor != nil {
			successors = []*cfg.Block{selectedSuccessor}
		}
		for _, successor := range successors {
			if clause, ok := successor.Stmt.(*ast.CaseClause); ok && successor.Kind == cfg.KindSwitchCaseBody && restrictedSwitchCases[clause] && !selectedSwitchCases[clause] {
				fallthroughEdge := cfgBlockBelongsToClause(block, fallthroughSources[clause])
				if !fallthroughEdge {
					continue
				}
			}
			queue = append(queue, successor)
		}
	}

	for block := range reachable {
		for index, node := range block.Nodes {
			if node.Pos() <= sink.Pos() && sink.End() <= node.End() {
				if panicIndex := parenthesizedBuiltinPanicIndex(info, block); panicIndex >= 0 && panicIndex < index {
					return "parenthesized panic terminates the containing CFG block", true
				}
				return "", false
			}
		}
	}
	return "no reachable CFG block contains the sink", true
}

func parenthesizedBuiltinPanicIndex(info *types.Info, block *cfg.Block) int {
	for index, node := range block.Nodes {
		exprStmt, ok := node.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := unwrapParens(exprStmt.X).(*ast.CallExpr)
		if !ok || call == exprStmt.X {
			continue
		}
		builtin, ok := calledObject(info, call.Fun).(*types.Builtin)
		if ok && builtin.Name() == "panic" {
			return index
		}
	}
	return -1
}

func cfgBlockBelongsToClause(block *cfg.Block, clause *ast.CaseClause) bool {
	if block == nil || clause == nil {
		return false
	}
	if block.Stmt != nil && clause.Pos() <= block.Stmt.Pos() && block.Stmt.End() <= clause.End() {
		return true
	}
	for _, node := range block.Nodes {
		if clause.Pos() <= node.Pos() && node.End() <= clause.End() {
			return true
		}
	}
	return false
}

func constantBool(info *types.Info, expr ast.Expr) (bool, bool) {
	if expr == nil {
		return false, false
	}
	value := info.Types[unwrapParens(expr)].Value
	if value == nil || value.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(value), true
}

func definiteBool(info *types.Info, expr ast.Expr, factSets ...map[types.Object]bool) (bool, bool) {
	expr = unwrapParens(expr)
	if value, known := constantBool(info, expr); known {
		return value, true
	}
	switch node := expr.(type) {
	case *ast.Ident:
		if len(factSets) > 0 {
			value, known := factSets[0][info.ObjectOf(node)]
			return value, known
		}
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			value, known := definiteBool(info, node.X, factSets...)
			return !value, known
		}
	case *ast.CallExpr:
		if len(node.Args) != 1 || !info.Types[node.Fun].IsType() || !booleanOnlyType(info.TypeOf(node)) {
			break
		}
		return definiteBool(info, node.Args[0], factSets...)
	case *ast.BinaryExpr:
		left, leftKnown := definiteBool(info, node.X, factSets...)
		right, rightKnown := definiteBool(info, node.Y, factSets...)
		switch node.Op {
		case token.LAND:
			if (leftKnown && !left) || (rightKnown && !right) {
				return false, true
			}
			if leftKnown && rightKnown {
				return true, true
			}
		case token.LOR:
			if (leftKnown && left) || (rightKnown && right) {
				return true, true
			}
			if leftKnown && rightKnown {
				return false, true
			}
		case token.EQL, token.NEQ:
			if leftKnown && rightKnown {
				equal := left == right
				if node.Op == token.NEQ {
					equal = !equal
				}
				return equal, true
			}
		}
	}
	return false, false
}

func booleanOnlyType(valueType types.Type) bool {
	if valueType == nil {
		return false
	}
	if basic, ok := valueType.Underlying().(*types.Basic); ok {
		return basic.Info()&types.IsBoolean != 0
	}
	parameter, ok := valueType.(*types.TypeParam)
	if !ok {
		return false
	}
	constraint, ok := parameter.Constraint().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	foundBoolean, valid := booleanConstraintEvidence(constraint)
	return valid && foundBoolean
}

func booleanConstraintEvidence(constraintType types.Type) (bool, bool) {
	switch constraint := constraintType.(type) {
	case *types.Union:
		if constraint.Len() == 0 {
			return false, false
		}
		for index := 0; index < constraint.Len(); index++ {
			basic, ok := constraint.Term(index).Type().Underlying().(*types.Basic)
			if !ok || basic.Info()&types.IsBoolean == 0 {
				return false, false
			}
		}
		return true, true
	case *types.Basic:
		return constraint.Info()&types.IsBoolean != 0, constraint.Info()&types.IsBoolean != 0
	case *types.Interface:
		constraint.Complete()
		foundBoolean := false
		for index := 0; index < constraint.NumEmbeddeds(); index++ {
			embedded := constraint.EmbeddedType(index)
			found, valid := booleanConstraintEvidence(embedded)
			if found {
				foundBoolean = true
			}
			if !valid {
				if _, isInterface := embedded.Underlying().(*types.Interface); isInterface {
					continue
				}
				return false, false
			}
		}
		return foundBoolean, true
	default:
		if underlying := constraintType.Underlying(); underlying != constraintType {
			return booleanConstraintEvidence(underlying)
		}
		return false, false
	}
}

func selectedConstantSwitchCase(info *types.Info, switchStmt *ast.SwitchStmt) ([]*ast.CaseClause, int, bool) {
	tag := switchStmt.Tag
	if tag == nil {
		tag = ast.NewIdent("true")
	}
	tagValue := info.Types[unwrapParens(tag)].Value
	if switchStmt.Tag == nil {
		tagValue = constant.MakeBool(true)
	}
	if tagValue == nil {
		return nil, -1, false
	}
	clauses := make([]*ast.CaseClause, 0, len(switchStmt.Body.List))
	defaultIndex := -1
	selectedIndex := -1
	for _, clauseNode := range switchStmt.Body.List {
		clause, ok := clauseNode.(*ast.CaseClause)
		if !ok {
			return nil, -1, false
		}
		index := len(clauses)
		clauses = append(clauses, clause)
		if len(clause.List) == 0 {
			defaultIndex = index
			continue
		}
		for _, expr := range clause.List {
			caseValue := info.Types[unwrapParens(expr)].Value
			if caseValue == nil {
				return nil, -1, false
			}
			if selectedIndex == -1 && constant.Compare(tagValue, token.EQL, caseValue) {
				selectedIndex = index
			}
		}
	}
	if selectedIndex == -1 {
		selectedIndex = defaultIndex
	}
	return clauses, selectedIndex, true
}

func rangeStmtProvablyEmpty(info *types.Info, statement ast.Stmt) bool {
	rangeStmt, ok := statement.(*ast.RangeStmt)
	if !ok {
		return false
	}
	rangeType := info.TypeOf(rangeStmt.X)
	if pointer, ok := rangeType.(*types.Pointer); ok {
		rangeType = pointer.Elem()
	}
	if rangeType != nil {
		if array, ok := rangeType.Underlying().(*types.Array); ok && array.Len() == 0 {
			return true
		}
	}
	if literal, ok := unwrapParens(rangeStmt.X).(*ast.CompositeLit); ok && len(literal.Elts) == 0 {
		switch info.TypeOf(literal).Underlying().(type) {
		case *types.Slice, *types.Map:
			return true
		}
	}
	if value := info.Types[unwrapParens(rangeStmt.X)].Value; value != nil {
		return (value.Kind() == constant.String && constant.StringVal(value) == "") ||
			(value.Kind() == constant.Int && constant.Sign(value) <= 0)
	}
	return false
}

func isInterfaceBroadcastCall(info *types.Info, call *ast.CallExpr, sseEventType types.Type) bool {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sseEventType == nil {
		return false
	}
	receiverType := info.TypeOf(sel.X)
	if receiverType == nil {
		return false
	}
	if pointer, pointerTypeOK := receiverType.(*types.Pointer); pointerTypeOK {
		receiverType = pointer.Elem()
	}
	if _, interfaceTypeOK := receiverType.Underlying().(*types.Interface); !interfaceTypeOK {
		return false
	}
	fn, functionOK := selectedObject(info, sel).(*types.Func)
	if !functionOK || fn.Name() != "Broadcast" {
		return false
	}
	sig, signatureOK := fn.Type().(*types.Signature)
	return signatureOK && sig.Params().Len() == 1 && types.Identical(sig.Params().At(0).Type(), sseEventType)
}

func directBroadcastNames(info *types.Info, call *ast.CallExpr, parents map[ast.Node]ast.Node, objects typedWiringObjects) ([]string, bool, error) {
	if len(call.Args) != 1 {
		return nil, false, fmt.Errorf("Broadcast must receive exactly one event")
	}
	expr := unwrapParens(call.Args[0])
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || objects.sseEventType == nil || !types.Identical(info.TypeOf(lit), objects.sseEventType) {
		return nil, false, fmt.Errorf("Broadcast argument must be a direct SSEEvent keyed literal")
	}
	var typeExpr ast.Expr
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, false, fmt.Errorf("SSEEvent literal must use keyed fields")
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || info.Uses[key] != objects.sseTypeField {
			continue
		}
		if typeExpr != nil {
			return nil, false, fmt.Errorf("SSEEvent literal assigns Type more than once")
		}
		typeExpr = kv.Value
	}
	if typeExpr == nil {
		return nil, false, fmt.Errorf("SSEEvent literal must assign Type")
	}
	if name, ok := constantString(info, typeExpr); ok {
		return []string{name}, false, nil
	}
	if bridgeCall, ok := unwrapParens(typeExpr).(*ast.CallExpr); ok &&
		objects.bridgeFunc != nil && calledObject(info, bridgeCall.Fun) == objects.bridgeFunc &&
		len(bridgeCall.Args) == 1 {
		if !bridgeUsesExactOnEventParameter(info, bridgeCall, parents, objects.onEventField) {
			return nil, false, fmt.Errorf("REST bridge argument must be the exact OnEvent callback event parameter")
		}
		if !bridgeUsesLiveDashboard(info, call, parents, objects) {
			return nil, false, fmt.Errorf("REST bridge must publish through the live dashboard SSE broadcaster")
		}
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("SSEEvent Type must be compile-time constant or the exact REST bridge")
}

func bridgeUsesExactOnEventParameter(info *types.Info, bridgeCall *ast.CallExpr, parents map[ast.Node]ast.Node, onEventField *types.Var) bool {
	arg, ok := unwrapParens(bridgeCall.Args[0]).(*ast.Ident)
	if !ok || info.Uses[arg] == nil || onEventField == nil {
		return false
	}
	for node := ast.Node(bridgeCall); node != nil; node = parents[node] {
		fn, ok := node.(*ast.FuncLit)
		if !ok {
			continue
		}
		if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 || len(fn.Type.Params.List[0].Names) == 0 {
			return false
		}
		param := fn.Type.Params.List[0].Names[0]
		if info.Defs[param] != info.Uses[arg] {
			return false
		}
		assign, ok := parents[fn].(*ast.AssignStmt)
		return ok && directOnEventBindingFromAssign(fn, assign, info, onEventField)
	}
	return false
}

func bridgeUsesLiveDashboard(info *types.Info, broadcastCall *ast.CallExpr, parents map[ast.Node]ast.Node, objects typedWiringObjects) bool {
	if objects.newDashboard == nil || objects.dashboardSSE == nil {
		return true
	}
	method, ok := unwrapParens(broadcastCall.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	sse, ok := unwrapParens(method.X).(*ast.SelectorExpr)
	if !ok || selectedObject(info, sse) != objects.dashboardSSE {
		return false
	}
	return expressionRootInitializedBy(info, sse.X, parents, objects.newDashboard, "dashboard")
}

func expressionRootInitializedBy(info *types.Info, expr ast.Expr, parents map[ast.Node]ast.Node, constructor *types.Func, expectedName string) bool {
	root, ok := unwrapParens(expr).(*ast.Ident)
	if !ok || constructor == nil || root.Name != expectedName {
		return false
	}
	obj := info.Uses[root]
	if obj == nil {
		return false
	}
	for ident, defined := range info.Defs {
		if defined != obj {
			continue
		}
		switch parent := parents[ident].(type) {
		case *ast.AssignStmt:
			for i, lhs := range parent.Lhs {
				if unwrapParens(lhs) != ident || i >= len(parent.Rhs) {
					continue
				}
				call, ok := unwrapParens(parent.Rhs[i]).(*ast.CallExpr)
				return ok && calledObject(info, call.Fun) == constructor
			}
		case *ast.ValueSpec:
			for i, name := range parent.Names {
				if name != ident || i >= len(parent.Values) {
					continue
				}
				call, ok := unwrapParens(parent.Values[i]).(*ast.CallExpr)
				return ok && calledObject(info, call.Fun) == constructor
			}
		}
	}
	return false
}

func directOnEventBinding(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node, info *types.Info, objects typedWiringObjects) bool {
	assign, ok := parents[sel].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || unwrapParens(assign.Lhs[0]) != sel || len(assign.Rhs) != 1 {
		return false
	}
	fn, ok := unwrapParens(assign.Rhs[0]).(*ast.FuncLit)
	field, fieldOK := selectedObject(info, sel).(*types.Var)
	if !ok || !fieldOK || !directOnEventBindingFromAssign(fn, assign, info, field) {
		return false
	}
	return objects.newRestServer == nil || expressionRootInitializedBy(info, sel.X, parents, objects.newRestServer, "restServer")
}

func directOnEventBindingFromAssign(fn *ast.FuncLit, assign *ast.AssignStmt, info *types.Info, onEventField *types.Var) bool {
	if assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || unwrapParens(assign.Rhs[0]) != fn {
		return false
	}
	sel, ok := unwrapParens(assign.Lhs[0]).(*ast.SelectorExpr)
	return ok && selectedObject(info, sel) == onEventField
}

func onEventUseIsSanctioned(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node, info *types.Info, objects typedWiringObjects) bool {
	parent := parents[sel]
	switch n := parent.(type) {
	case *ast.CallExpr:
		if n.Fun == sel {
			return true
		}
		if objects.retrievalHelper != nil && calledObject(info, n.Fun) == objects.retrievalHelper {
			for _, arg := range n.Args {
				if unwrapParens(arg) == sel {
					return true
				}
			}
		}
	case *ast.BinaryExpr:
		return isNilIdent(n.X) || isNilIdent(n.Y)
	}
	return false
}

func astParents(file *ast.File) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func calledObject(info *types.Info, expr ast.Expr) types.Object {
	expr = unwrapParens(expr)
	switch n := expr.(type) {
	case *ast.Ident:
		return info.Uses[n]
	case *ast.SelectorExpr:
		return selectedObject(info, n)
	}
	return nil
}

func selectedObject(info *types.Info, sel *ast.SelectorExpr) types.Object {
	if selection := info.Selections[sel]; selection != nil {
		return selection.Obj()
	}
	return info.Uses[sel.Sel]
}

func constantString(info *types.Info, expr ast.Expr) (string, bool) {
	value := info.Types[unwrapParens(expr)].Value
	if value == nil || value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(value), true
}

func unwrapParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func isNilIdent(expr ast.Expr) bool {
	ident, ok := unwrapParens(expr).(*ast.Ident)
	return ok && ident.Name == "nil"
}

func newTypesInfo() *types.Info {
	return &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
}

func typedEventConstants(t *testing.T, pkg *packages.Package, eventType types.Type) []string {
	t.Helper()
	scopeNames := pkg.Types.Scope().Names()
	names := make([]string, 0, len(scopeNames))
	for _, name := range scopeNames {
		obj, ok := pkg.Types.Scope().Lookup(name).(*types.Const)
		if !ok || !types.Identical(obj.Type(), eventType) {
			continue
		}
		require.Equal(t, constant.String, obj.Val().Kind())
		names = append(names, constant.StringVal(obj.Val()))
	}
	sort.Strings(names)
	return names
}

func requirePackage(t *testing.T, pkgs []*packages.Package, path string) *packages.Package {
	t.Helper()
	for _, pkg := range pkgs {
		if pkg.PkgPath == path {
			return pkg
		}
	}
	t.Fatalf("missing loaded package %s", path)
	return nil
}

func requireNamedType(t *testing.T, pkg *packages.Package, name string) *types.Named {
	t.Helper()
	return requireNamedObject(t, pkg.Types.Scope().Lookup(name), name)
}

func requireNamedTypeFromTypes(t *testing.T, pkg *types.Package, name string) *types.Named {
	t.Helper()
	return requireNamedObject(t, pkg.Scope().Lookup(name), name)
}

func requireNamedObject(t *testing.T, obj types.Object, name string) *types.Named {
	t.Helper()
	require.NotNil(t, obj, "missing type %s", name)
	named, ok := obj.Type().(*types.Named)
	require.True(t, ok, "%s is not a named type", name)
	return named
}

func requireMethod(t *testing.T, named *types.Named, name string) *types.Func {
	t.Helper()
	obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(named), true, named.Obj().Pkg(), name)
	method, ok := obj.(*types.Func)
	require.True(t, ok, "missing method %s.%s", named.Obj().Name(), name)
	return method
}

func requireStructField(t *testing.T, named *types.Named, name string) *types.Var {
	t.Helper()
	obj, _, _ := types.LookupFieldOrMethod(named, true, named.Obj().Pkg(), name)
	field, ok := obj.(*types.Var)
	require.True(t, ok && field.IsField(), "missing field %s.%s", named.Obj().Name(), name)
	return field
}

func requireFunc(t *testing.T, pkg *packages.Package, name string) *types.Func {
	t.Helper()
	fn, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	require.True(t, ok, "missing function %s.%s", pkg.PkgPath, name)
	return fn
}

func requireFuncFromTypes(t *testing.T, pkg *types.Package, name string) *types.Func {
	t.Helper()
	fn, ok := pkg.Scope().Lookup(name).(*types.Func)
	require.True(t, ok, "missing function %s.%s", pkg.Path(), name)
	return fn
}

func (s typedWiringScan) sitesByName() string {
	grouped := map[string][]string{}
	for _, site := range s.emits {
		grouped[site.name] = append(grouped[site.name], site.pos)
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "%s: %s\n", name, strings.Join(grouped[name], ", "))
	}
	return out.String()
}

func eventTypeStrings(types []EventType) []string {
	out := make([]string, 0, len(types))
	for _, eventType := range types {
		out = append(out, string(eventType))
	}
	return out
}

func assertSameEventSet(t *testing.T, want, got []string, wantLabel, gotLabel, detail string) {
	t.Helper()
	wantSet := uniqueSorted(want)
	gotSet := uniqueSorted(got)
	if assert.ObjectsAreEqual(wantSet, gotSet) {
		return
	}
	assert.Equal(t, wantSet, gotSet,
		"SSE wiring mismatch: missing from %s=%v; missing from %s=%v\n%s",
		gotLabel, difference(wantSet, gotSet), wantLabel, difference(gotSet, wantSet), detail)
}

func assertNoDuplicates(t *testing.T, names []string, label string) {
	t.Helper()
	seen := map[string]bool{}
	for _, name := range names {
		assert.False(t, seen[name], "%s lists %q more than once", label, name)
		seen[name] = true
	}
}

func uniqueSorted(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func difference(from, remove []string) []string {
	excluded := map[string]bool{}
	for _, name := range remove {
		excluded[name] = true
	}
	var out []string
	for _, name := range from {
		if !excluded[name] {
			out = append(out, name)
		}
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	return root
}
