package tx

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// This file is the adversarial half of the fence's test surface: every fixture
// here is something a HOSTILE OR BROKEN RPC PEER can actually send — a replayed
// envelope about someone else's transaction, an oversized body inside the
// unstoppable retry loop, remote text carrying terminal control sequences —
// and every assertion is about what must NOT happen: no lift, no leak, no
// forged log line. The happy paths live in nonce_fence_resolver_test.go; this
// file exists because each of these shapes, in some form, defeated an earlier
// revision of this code.

// hostileControls is the injection payload used across this file: CR rewinds a
// terminal cursor over the line already written, ESC opens an ANSI sequence in
// any viewer, DEL survives naive filters. Deliberately contains NO space, tab,
// newline or double-quote — those were the only characters the superseded
// quoting check looked for, so this value went to the log writer RAW under it.
const hostileControls = "\rSAGE:_nonce_fence_event=fence_lift_forged=yes\x1b[2K\x7f"

// signedFixtureTx returns a REAL signed, encoded transaction whose hex is long
// enough to engage the long-hex-run scrubber pass (fenceHexKeepMax). A short
// placeholder byte string exercises only the exact-match pass, and a leak
// regression that never touches the heuristic can pass with the heuristic
// broken outright — which is exactly what a 12-byte fixture did.
func signedFixtureTx(t *testing.T) (encoded []byte, sentHex string) {
	t.Helper()
	sk := newLeaseTestKey(t)
	ptx := sampleSubmitTx()
	if err := SignTx(ptx, sk); err != nil {
		t.Fatalf("sign fixture tx: %v", err)
	}
	encoded, err := EncodeTx(ptx)
	if err != nil {
		t.Fatalf("encode fixture tx: %v", err)
	}
	if len(encoded) <= fenceHexKeepMax {
		t.Fatalf("fixture transaction is %d bytes; it must exceed fenceHexKeepMax (%d) or the "+
			"long-hex-run pass goes untested", len(encoded), fenceHexKeepMax)
	}
	return encoded, hex.EncodeToString(encoded)
}

// assertNoRawControls scans BYTES, not substrings: the defect being pinned is
// bytes reaching a log writer or status surface, so the assertion must look at
// exactly what was written. Only '\n' is legal, and only as a line terminator
// (emitFenceEvent's own framing).
func assertNoRawControls(t *testing.T, surface, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\n' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			t.Fatalf("%s carries raw control byte %#x at offset %d; a terminal or log viewer "+
				"rendering it can be rewound or repainted into a forged line: %q", surface, b, i, s)
		}
	}
}

// TestEmitFenceEvent_ControlCharactersCannotForgeLogLines pins the field
// writer's quoting decision at the byte level. The values that reach these
// fields include RPC-derived details — remote text — and the superseded check
// quoted only on space/tab/newline/quote, a character SET. CR, ESC and DEL all
// passed raw: a detail containing \r could rewind the cursor and overwrite the
// line just emitted, i.e. forge a fence event that never happened. The fix is
// an allowlist (quote anything not printable-and-plain), so this test asserts
// on the EMITTED BYTES: no raw control may reach the writer at all, invalid
// UTF-8 (how bare C1 controls arrive) must be escaped, and the event must
// still be one parseable line carrying the hostile value inside its quotes.
func TestEmitFenceEvent_ControlCharactersCannotForgeLogLines(t *testing.T) {
	logged := captureFenceLog(t)

	// A raw C1 control (0x85, NEL) is invalid UTF-8 on its own; ranging over
	// the string yields RuneError per byte, which must force quoting so
	// strconv.Quote renders it as an escape instead of passing the byte through.
	const c1 = "x\x85y"

	emitFenceEvent("adversarial_probe",
		fenceKV("signer", "aabbccdd"),
		fenceKV("detail", hostileControls),
		fenceKV("note", c1))

	out := logged.String()
	if out == "" {
		t.Fatal("emitFenceEvent wrote nothing; sanitizing by dropping the event trades a forgery for a mystery")
	}
	assertNoRawControls(t, "the fence event line", out)
	if strings.IndexByte(out, 0x85) >= 0 {
		t.Fatalf("a raw C1 control byte reached the log writer unescaped: %q", out)
	}
	// One event in, one line out, terminated: if the hostile value had broken
	// out of its field, the forged "event=fence_lift" would appear as a second
	// event token on the wire.
	if got := strings.Count(out, "\n"); got != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected exactly one terminated line, got %d newline(s): %q", got, out)
	}
	if got := strings.Count(out, " event="); got != 1 {
		// The line's own framing is "SAGE: nonce_fence event=<name>" — exactly
		// one space-separated "event=" token. A second one can only come from
		// injected text that escaped quoting and forged a field of its own.
		t.Fatalf("expected exactly one event token, got %d — remote text forged event fields: %q", got, out)
	}
	if !strings.Contains(out, "detail="+strconv.Quote(hostileControls)) {
		t.Fatalf("the hostile value must survive INSIDE its quoted field — dropping it would hide "+
			"the evidence an operator needs: %q", out)
	}
	if !strings.Contains(out, "signer=aabbccdd") {
		t.Fatalf("a plain single-token value should stay raw and greppable: %q", out)
	}
}

// TestScrubFenceText_StripsEveryControlRune pins the scrubber half of the same
// defect: values scrubbed here are stored in fence records and surfaced through
// FencedSigners() into status payloads, where a rendering client — not
// emitFenceEvent — decides how they appear. Quoting at the log writer cannot
// protect those surfaces, so the stored text itself must carry no control
// runes, with no exceptions (extending a character set is how this exact bug
// shipped twice).
func TestScrubFenceText_StripsEveryControlRune(t *testing.T) {
	in := "line1" + hostileControls + "line2\tline3\nline4\u202efile5\u2066line6"
	got := scrubFenceText(in, nil)
	if strings.ContainsFunc(got, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) {
		t.Fatalf("scrubFenceText let control or Unicode format runes through: %q", got)
	}
	// The readable content must survive: scrubbing by deletion of everything
	// would be indistinguishable from an empty diagnostic.
	for _, want := range []string{"line1", "line2", "line3", "line4", "file5", "line6"} {
		if !strings.Contains(got, want) {
			t.Fatalf("scrubFenceText destroyed readable content %q: %q", want, got)
		}
	}
}

// chunkHexEvery re-chunks s into n-character pieces joined by sep — the
// transformation a hostile proxy applies to slip a payload's hex past the
// long-run scrubber pass, whose threshold is per-run.
func chunkHexEvery(s string, n int, sep string) (joined string, chunks []string) {
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return strings.Join(chunks, sep), chunks
}

// TestScrubFenceText_ChunkedHexCannotEvadeTheBudget pins the fourth scrubber
// pass at the unit level: the signed payload's hex split into sub-threshold
// runs — by single separators (the reassembly rule) or by wide separators at
// payload density (the density rule) — must not survive into a fence detail
// in ANY fragment, and the redaction must be visible. Contiguous-hex fixtures
// alone proved nothing here: every chunk passed the exact-match, tx= and
// long-run passes individually, and up to fenceDetailMax bytes of the signed
// transaction reached the stored detail and its re-logging cadence.
func TestScrubFenceText_ChunkedHexCannotEvadeTheBudget(t *testing.T) {
	_, sentHex := signedFixtureTx(t)
	for _, tc := range []struct {
		name string
		n    int
		sep  string
	}{
		// Each chunk is comfortably under fenceHexKeepMax; single-byte
		// separators are bridged by the reassembly rule.
		{"hyphen every 100", 100, "-"},
		{"space every 64", 64, " "},
		// A control-byte separator becomes a single space in the control pass,
		// which is exactly the bridged shape.
		{"carriage return every 100", 100, "\r"},
		// Wide separators defeat reassembly; density catches the payload.
		{"double hyphen every 100", 100, "--"},
		{"word gaps every 96", 96, " chunk "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined, chunks := chunkHexEvery(sentHex, tc.n, tc.sep)
			got := scrubFenceText("replay of broadcast request: "+joined, nil)
			for i, chunk := range chunks {
				if strings.Contains(strings.ToLower(got), strings.ToLower(chunk)) {
					t.Fatalf("chunk %d of the signed transaction's hex survived scrubbing "+
						"(a partial payload leak repeating for the life of the fence is no "+
						"better than a full one): %q", i, got)
				}
			}
			if !strings.Contains(got, "[redacted") {
				t.Fatalf("the payload was dropped silently rather than visibly redacted: %q", got)
			}
		})
	}
}

// TestScrubFenceText_LegitimateDiagnosticsSurviveTheChunkPass is the other
// half of the fourth pass's contract: the backstop must not eat the
// diagnostics an operator actually reads. Each fixture is a REAL detail shape
// this package or its adopters produce — identifier-bearing, digit-heavy, or
// already carrying an earlier pass's redaction marker — and each must pass
// through unchanged.
func TestScrubFenceText_LegitimateDiagnosticsSurviveTheChunkPass(t *testing.T) {
	fullHash := strings.Repeat("ab12cd34", 8) // 64 chars: a lone hash is 100% hex and must survive
	for _, legit := range []string{
		"cometbft /tx answered about a different transaction (want deadbeef…, got 12ab34cd…): not proof of this one's fate",
		`Get "http://127.0.0.1:26657/broadcast_tx_commit?tx=0x[redacted signed tx]": dial tcp 127.0.0.1:26657: connect: connection refused`,
		"resubmit answered CheckTx code 4 at height 128841: nonce at or below the committed floor",
		"reported hash " + fullHash + " at height 12",
	} {
		if got := scrubFenceText(legit, nil); got != legit {
			t.Fatalf("the chunk backstop destroyed a legitimate diagnostic:\n in: %q\nout: %q", legit, got)
		}
	}
}

// TestCometTxResolver_ChunkedHexPayloadNeverSurvives drives the chunking
// evasion end to end, through the resolver path whose output actually feeds
// fence records: a hostile proxy answers the reconciler's re-submit with an
// error envelope whose data is the request's own tx hex re-chunked every 100
// characters by hyphens. Every chunk individually clears the exact-match, tx=
// and long-run passes, so before the chunk backstop this stored a partial
// signed payload in the fence detail and re-emitted it on every held-fence
// report for as long as the fence stood.
func TestCometTxResolver_ChunkedHexPayloadNeverSurvives(t *testing.T) {
	encoded, sentHex := signedFixtureTx(t)
	joined, chunks := chunkHexEvery(sentHex, 100, "-")
	forgedData, jsonErr := json.Marshal("upstream refused: " + joined)
	if jsonErr != nil {
		t.Fatalf("encode fixture: %v", jsonErr)
	}

	fake, endpoint := newFakeComet(t)
	fake.setHandlers(
		func(string) (int, string) { return 500, cometNotFound },
		func(string) (int, string) {
			return 200, `{"error":{"code":-32603,"message":"Internal error","data":` + string(forgedData) + `}}`
		})

	outcome, err := resolveWithFake(t, endpoint, encoded)
	if err != nil {
		t.Fatalf("resolve returned an error rather than an unresolved outcome: %v", err)
	}
	if outcome.Verdict != TxVerdictUnresolved {
		t.Fatalf("got %v, want unresolved: a proxy echo proves nothing about these bytes' fate", outcome.Verdict)
	}
	lowered := strings.ToLower(outcome.Detail)
	for i, chunk := range chunks {
		if strings.Contains(lowered, strings.ToLower(chunk)) {
			t.Fatalf("chunk %d of the signed transaction's hex reached the fence detail: %q", i, outcome.Detail)
		}
	}
	if !strings.Contains(outcome.Detail, "[redacted") {
		t.Fatalf("the payload was dropped silently rather than visibly redacted: %q", outcome.Detail)
	}
}

// TestCometTxResolver_Oversized500BodyStaysUnresolved is the 500 half of the
// body cap. CometBFT delivers real answers ("tx not found", mempool refusals)
// as 500 with a JSON-RPC error envelope, so 500 bodies reach the decoder — and
// before the cap, a 500 whose oversized body smuggled a perfectly-formed
// RESULT envelope (bound hash, positive height, zero codes) was decoded and
// LIFTED on. Both hazards at once: an allocation amplifier inside the
// unstoppable retry loop, and a proxy's 500 body treated as consensus proof.
// Oversized is not proof, 500-with-result is not CometBFT: unresolved, fence
// held.
func TestCometTxResolver_Oversized500BodyStaysUnresolved(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	encoded := []byte("oversized-500-answer")
	boundHash := cometHashHexForTest(encoded)
	pad := strings.Repeat("a", CometRPCMaxResponseBytes+(1<<20))

	fake.setHandlers(
		func(string) (int, string) {
			return 500, `{"pad":"` + pad + `","result":{"hash":"` + boundHash + `","height":"3","tx_result":{"code":0}}}`
		},
		func(string) (int, string) {
			return 500, `{"pad":"` + pad + `","result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
				boundHash + `","height":"3"}}`
		})

	outcome, err := resolveWithFake(t, endpoint, encoded)
	if err != nil {
		t.Fatalf("resolve returned an error rather than an unresolved outcome: %v", err)
	}
	if outcome.Verdict != TxVerdictUnresolved {
		t.Fatalf("got %v, want unresolved: an oversized 500 body must never lift a fence", outcome.Verdict)
	}
	if outcome.Detail == "" {
		t.Fatal("an unresolved outcome with no detail makes a held fence undiagnosable")
	}
}

// TestCometTxResolver_AdversarialAnswersNeverLiftOrLeak drives the resolver
// with a REAL signed transaction against the response shapes a hostile or
// replaying RPC peer produces, and asserts BOTH halves of the contract on each:
// no verdict (the fence holds), and no trace of the signed payload in anything
// the resolver reports (its detail feeds fence records, status payloads and
// log lines that repeat for as long as the fence stands). Marker-presence
// alone proves nothing — a scrubber can stamp a marker and still leak — so the
// payload's ABSENCE is asserted explicitly, against the full hex in both cases.
func TestCometTxResolver_AdversarialAnswersNeverLiftOrLeak(t *testing.T) {
	encoded, sentHex := signedFixtureTx(t)
	boundHash := cometHashHexForTest(encoded)
	pad := strings.Repeat(sentHex, CometRPCMaxResponseBytes/len(sentHex)+1)

	// The forged-URL error data a proxy replaying the request line would echo,
	// with the control-char forgery a hostile one can append. JSON-encoded so
	// the raw CR/ESC/DEL survive the envelope intact.
	forgedData, jsonErr := json.Marshal("replay of GET /broadcast_tx_commit?tx=0x" + sentHex + hostileControls)
	if jsonErr != nil {
		t.Fatalf("encode fixture: %v", jsonErr)
	}

	for _, tc := range []struct {
		name       string
		lookup     func(string) (int, string)
		submit     func(string) (int, string)
		wantMarker bool
	}{
		{
			// Every field zero-values; nothing here may assemble into a verdict
			// or echo anything.
			name:   "partial envelope with an empty result",
			lookup: func(string) (int, string) { return 200, `{"result":{}}` },
			submit: func(string) (int, string) { return 200, `{"result":{}}` },
		},
		{
			// The reported hash IS the payload: a confused peer echoing the
			// request back as the answer. The superseded code required only a
			// nonempty hash, so this envelope lifted — and quoting the reported
			// value into the mismatch diagnostic would leak the transaction.
			name:   "success envelope whose hash echoes the signed payload",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
					sentHex + `","height":"12"}}`
			},
		},
		{
			// The error envelope echoing the broadcast URL plus a control-char
			// forgery — remote text that lands verbatim in the resolver's
			// detail unless scrubbed at the source.
			name:   "error envelope echoing the broadcast URL with control injection",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"error":{"code":-32603,"message":"Internal error","data":` + string(forgedData) + `}}`
			},
			wantMarker: true,
		},
		{
			// An oversized body built FROM the payload, wrapped around an
			// otherwise-perfect commit proof: size alone must disqualify it,
			// and none of the payload may surface in the failure diagnostics.
			name:   "oversized body carrying the signed payload",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"pad":"` + pad + `","result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
					boundHash + `","height":"3"}}`
			},
		},
		{
			// Decode must consume the whole document. Accepting the first valid
			// value lets a proxy append a second envelope while still lifting on
			// the first one.
			name:   "valid proof followed by a second JSON document",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
					boundHash + `","height":"3"}}{}`
			},
		},
		{
			// A proof at the front followed by more than the cap of whitespace
			// used to evade limited.N because Decode stopped after the object.
			name:   "valid proof followed by an oversized suffix",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
					boundHash + `","height":"3"}}` + strings.Repeat(" ", CometRPCMaxResponseBytes+1)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, endpoint := newFakeComet(t)
			fake.setHandlers(tc.lookup, tc.submit)

			outcome, err := resolveWithFake(t, endpoint, encoded)
			if err != nil {
				t.Fatalf("resolve returned an error rather than an unresolved outcome: %v", err)
			}
			if outcome.Verdict != TxVerdictUnresolved {
				t.Fatalf("got %v, want unresolved: nothing in this response proves these bytes' fate",
					outcome.Verdict)
			}
			if outcome.Detail == "" {
				t.Fatal("an unresolved outcome with no detail makes a held fence undiagnosable")
			}
			lowered := strings.ToLower(outcome.Detail)
			if strings.Contains(lowered, sentHex) {
				t.Fatalf("the resolver's detail carries the signed transaction's hex: %q", outcome.Detail)
			}
			assertNoRawControls(t, "the resolver's detail", outcome.Detail)
			if tc.wantMarker && !strings.Contains(outcome.Detail, redactedTxMarker) &&
				!strings.Contains(outcome.Detail, "[redacted") {
				t.Fatalf("the payload was dropped silently rather than visibly redacted: %q", outcome.Detail)
			}
		})
	}
}
