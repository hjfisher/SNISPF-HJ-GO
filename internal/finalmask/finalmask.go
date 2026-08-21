package finalmask

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// Int32Range is a [from, to] integer range; Pick returns a random value.
type Int32Range struct {
	From int
	To   int
}

// Pick returns a random value within the range (From when To <= From).
func (r *Int32Range) Pick() int {
	if r.To <= r.From {
		return r.From
	}
	return r.From + rand.Intn(r.To-r.From+1)
}

// ParseInt32Range parses "3", "3-5", "10-20" or a number string into a range.
func ParseInt32Range(value string) (*Int32Range, error) {
	text := strings.TrimSpace(value)
	if idx := strings.Index(text, "-"); idx >= 0 {
		a, errA := strconv.Atoi(strings.TrimSpace(text[:idx]))
		b, errB := strconv.Atoi(strings.TrimSpace(text[idx+1:]))
		if errA != nil || errB != nil {
			return nil, fmt.Errorf("finalmask: bad range %q", value)
		}
		return &Int32Range{From: a, To: b}, nil
	}
	v, err := strconv.Atoi(text)
	if err != nil {
		return nil, fmt.Errorf("finalmask: bad range %q", value)
	}
	return &Int32Range{From: v, To: v}, nil
}

// FragmentLayer is one finalmask "fragment" layer (mirrors xray's
// fragmentConn).
type FragmentLayer struct {
	tlshello      bool
	packetsFrom   int
	packetsTo     int
	lengths       []*Int32Range
	delays        []*Int32Range
	maxSplit      *Int32Range
	allDelaysZero bool
	count         int
}

// NewFragmentLayer builds a layer from a settings map (JSON object).
func NewFragmentLayer(settings map[string]interface{}) (*FragmentLayer, error) {
	f := &FragmentLayer{}
	packets := strings.TrimSpace(stringValue(settings["packets"]))
	switch {
	case strings.EqualFold(packets, "tlshello"):
		f.tlshello = true
		f.packetsFrom, f.packetsTo = 1, 1
	case packets == "":
		f.packetsFrom, f.packetsTo = 0, 0
	default:
		a, b, err := parseRangeStr(packets)
		if err != nil {
			return nil, fmt.Errorf("finalmask: bad packets range %q", packets)
		}
		f.packetsFrom, f.packetsTo = a, b
	}

	for _, x := range asList(settings["lengths"]) {
		r, err := ParseInt32Range(x)
		if err != nil {
			return nil, err
		}
		f.lengths = append(f.lengths, r)
	}
	for _, x := range asList(settings["delays"]) {
		r, err := ParseInt32Range(x)
		if err != nil {
			return nil, err
		}
		f.delays = append(f.delays, r)
	}
	r, err := ParseInt32Range(stringValue(settings["maxSplit"]))
	if err != nil {
		r = &Int32Range{From: 0, To: 0}
	}
	if stringValue(settings["maxSplit"]) == "" {
		r = &Int32Range{From: 0, To: 0}
	}
	f.maxSplit = r

	if len(f.lengths) == 0 {
		f.lengths = []*Int32Range{{From: 1, To: 1}}
	}
	if len(f.delays) == 0 {
		f.delays = []*Int32Range{{From: 0, To: 0}}
	}
	f.allDelaysZero = true
	for _, d := range f.delays {
		if d.To != 0 {
			f.allDelaysZero = false
			break
		}
	}
	return f, nil
}

// Reset resets the per-connection write counter.
func (f *FragmentLayer) Reset() { f.count = 0 }

// Emission is one masked chunk (data + delay_ms). data may be empty for
// "idle" rounds.
type Emission struct {
	Data    []byte
	DelayMS int
}

// Process masks one TCP write, returning the emissions.
func (f *FragmentLayer) Process(chunk []byte) []Emission {
	f.count++
	if f.tlshello {
		return f.processTLSHello(chunk)
	}
	return f.processStream(chunk)
}

func (f *FragmentLayer) pickLength(i int) int {
	if i < len(f.lengths) {
		return f.lengths[i].Pick()
	}
	return f.lengths[len(f.lengths)-1].Pick()
}

func (f *FragmentLayer) pickDelay(i int) int {
	if i < len(f.delays) {
		return f.delays[i].Pick()
	}
	return f.delays[len(f.delays)-1].Pick()
}

func (f *FragmentLayer) processTLSHello(p []byte) []Emission {
	if f.count != 1 || len(p) <= 5 || p[0] != 0x16 {
		return []Emission{{Data: p, DelayMS: 0}}
	}
	recordLen := 5 + (int(p[3])<<8 | int(p[4]))
	if len(p) < recordLen {
		return []Emission{{Data: p, DelayMS: 0}}
	}

	data := p[5:recordLen]
	maxSplit := f.maxSplit.Pick()
	var emissions []Emission
	var concat []byte
	splitNum := 0
	i := 0
	from := 0
	n := len(data)

	for from < n {
		length := f.pickLength(i)
		delay := f.pickDelay(i)

		if length <= 0 && i < len(f.lengths)-1 {
			if delay > 0 {
				emissions = append(emissions, Emission{DelayMS: delay})
			}
			i++
			continue
		}

		splitNum++
		to := from + length
		if to > n || (maxSplit > 0 && splitNum >= maxSplit) {
			to = n
		}
		l := to - from

		record := []byte{p[0], p[1], p[2], byte(l >> 8), byte(l)}
		record = append(record, data[from:to]...)
		from = to

		if delay == 0 && f.allDelaysZero {
			concat = append(concat, record...)
		} else {
			emissions = append(emissions, Emission{Data: record, DelayMS: delay})
		}
		i++
	}

	if len(concat) > 0 {
		emissions = append(emissions, Emission{Data: concat})
	}

	if len(p) > recordLen {
		emissions = append(emissions, Emission{Data: p[recordLen:]})
	}

	if len(emissions) == 0 {
		return []Emission{{Data: p}}
	}
	return emissions
}

func (f *FragmentLayer) appliesStream() bool {
	if f.packetsFrom == 0 && f.packetsTo == 0 {
		return true
	}
	return f.packetsFrom <= f.count && f.count <= f.packetsTo
}

func (f *FragmentLayer) processStream(p []byte) []Emission {
	if !f.appliesStream() {
		return []Emission{{Data: p, DelayMS: 0}}
	}
	n := len(p)
	if n == 0 {
		return []Emission{{Data: p, DelayMS: 0}}
	}

	maxSplit := f.maxSplit.Pick()
	var emissions []Emission
	splitNum := 0
	i := 0
	from := 0

	for from < n {
		length := f.pickLength(i)
		delay := f.pickDelay(i)

		if length <= 0 && i < len(f.lengths)-1 {
			if delay > 0 {
				emissions = append(emissions, Emission{DelayMS: delay})
			}
			i++
			continue
		}

		splitNum++
		to := from + length
		if to > n || (maxSplit > 0 && splitNum >= maxSplit) {
			to = n
		}
		emissions = append(emissions, Emission{Data: p[from:to], DelayMS: delay})
		from = to
		i++
	}
	return emissions
}

// FinalMasker composes fragment layers and applies them to outgoing writes.
// Layers are listed outermost-first; data is processed by the outermost layer
// first, each layer's emissions feeding the next layer down.
type FinalMasker struct {
	layers []*FragmentLayer
}

// NewFinalMasker builds a masker from raw config rules (a []interface{} of
// rule maps). Returns nil when no usable layers exist.
func NewFinalMasker(rules []interface{}) *FinalMasker {
	var layers []*FragmentLayer
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(stringValue(rule["type"])), "fragment") {
			continue
		}
		settings, _ := rule["settings"].(map[string]interface{})
		if settings == nil {
			settings = map[string]interface{}{}
		}
		layer, err := NewFragmentLayer(settings)
		if err != nil {
			continue
		}
		layers = append(layers, layer)
	}
	if len(layers) == 0 {
		return nil
	}
	for _, l := range layers {
		l.Reset()
	}
	return &FinalMasker{layers: layers}
}

// LayerCount returns the number of layers (for diagnostics).
func (m *FinalMasker) LayerCount() int {
	if m == nil {
		return 0
	}
	return len(m.layers)
}

// Clone returns a per-connection copy with fresh per-layer counters.
func (m *FinalMasker) Clone() *FinalMasker {
	if m == nil {
		return nil
	}
	layers := make([]*FragmentLayer, len(m.layers))
	for i, l := range m.layers {
		cp := *l
		cp.count = 0
		layers[i] = &cp
	}
	return &FinalMasker{layers: layers}
}

// Send pushes data through the mask layers, calling sink for each masked
// chunk and sleeping for the inter-fragment delays.
func (m *FinalMasker) Send(sink func([]byte) error, data []byte) error {
	return m.sendThrough(m.layers, sink, data)
}

func (m *FinalMasker) sendThrough(layers []*FragmentLayer, sink func([]byte) error, data []byte) error {
	if len(layers) == 0 {
		return sink(data)
	}
	outer := layers[0]
	for _, em := range outer.Process(data) {
		if len(em.Data) > 0 {
			if err := m.sendThrough(layers[1:], sink, em.Data); err != nil {
				return err
			}
		}
		if em.DelayMS > 0 {
			time.Sleep(time.Duration(em.DelayMS) * time.Millisecond)
		}
	}
	return nil
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func parseRangeStr(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "-"); idx >= 0 {
		a, errA := strconv.Atoi(strings.TrimSpace(s[:idx]))
		b, errB := strconv.Atoi(strings.TrimSpace(s[idx+1:]))
		if errA != nil || errB != nil {
			return 0, 0, fmt.Errorf("bad range %q", s)
		}
		return a, b, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, err
	}
	return v, v, nil
}

func asList(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []interface{}:
		var out []string
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return t
	case string:
		var out []string
		repl := strings.ReplaceAll(t, ",", " ")
		for _, x := range strings.Fields(repl) {
			out = append(out, x)
		}
		return out
	default:
		return []string{fmt.Sprint(v)}
	}
}
