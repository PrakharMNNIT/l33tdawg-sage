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
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", fixturePreamble(body), parser.AllErrors)
	require.NoError(t, err)
	info := newTypesInfo()
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("fixture", fset, []*ast.File{file}, info)
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
	scanTypedFile("", "fixture.go", fset, file, info, objects, &scan)
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
	var body *ast.BlockStmt
	for node := sink; node != nil; node = parents[node] {
		switch function := node.(type) {
		case *ast.FuncDecl:
			body = function.Body
		case *ast.FuncLit:
			body = function.Body
		}
		if body != nil {
			break
		}
	}
	if body == nil {
		return "sink has no enclosing function body", true
	}

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
				if value, known := constantBool(info, condition); known && !isSwitchCaseValue {
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
