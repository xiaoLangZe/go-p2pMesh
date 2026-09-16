package stun

import (
	"fmt"
	"net"
	"sort"
	"time"
)

// PortSample records one observed external port along with the destination
// it was observed against. The sequence of ports observed against different
// destinations reveals the NAT's port allocation strategy.
type PortSample struct {
	Port        int
	Destination string
	Timestamp   time.Time
}

// PortPrediction holds the result of analysing a sequence of port samples.
type PortPrediction struct {
	Pattern     PortPattern
	NextPort    int
	WindowStart int
	WindowEnd   int
	Samples     []PortSample
	Deltas      []int
}

// PortPattern classifies the observed allocation strategy.
type PortPattern string

const (
	PatternLinear       PortPattern = "linear"
	PatternCyclic       PortPattern = "cyclic"
	PatternRandom       PortPattern = "random"
	PatternInsufficient PortPattern = "insufficient"
)

// SamplePorts sends Binding Requests to multiple STUN servers using the same
// socket, collecting the observed source port for each. This is the probing
// phase described in DESIGN.md §11.4 and §12.3.
//
// The samples are taken against different destinations so the port deltas
// reveal how the NAT allocates ports per destination. A symmetric NAT that
// uses predictable allocation (e.g., linear increment) can be predicted.
//
// sampleCount is the desired number of samples (default 12, range 4–32 per
// the design). The actual count is capped by the number of available STUN
// servers — sampling more destinations than exist is meaningless.
func SamplePorts(pool *Pool, conn net.PacketConn, sampleCount int, timeout time.Duration) ([]PortSample, error) {
	servers := pool.All()
	if len(servers) < 2 {
		return nil, fmt.Errorf("need at least 2 STUN servers, got %d", len(servers))
	}

	if sampleCount < 4 {
		sampleCount = 4
	}
	if sampleCount > 32 {
		sampleCount = 32
	}
	if sampleCount > len(servers) {
		sampleCount = len(servers)
	}

	samples := make([]PortSample, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		srv := servers[i%len(servers)]
		c := NewStunClient(srv.Addr, timeout)
		addr, err := c.Binding(conn)
		if err != nil {
			continue
		}
		samples = append(samples, PortSample{
			Port:        portFromAddr(addr),
			Destination: srv.Addr,
			Timestamp:   time.Now(),
		})
	}

	if len(samples) < 2 {
		return nil, fmt.Errorf("only got %d valid samples", len(samples))
	}

	return samples, nil
}

// AnalyzePortSequence examines the port samples and classifies the NAT's
// allocation pattern. Returns a prediction of the next port and a window
// for the prediction.
//
// The analysis:
//  1. Sort samples by timestamp.
//  2. Compute deltas between consecutive ports.
//  3. If deltas are nearly constant (low variance), classify as linear and
//     predict the next port as last_port + delta.
//  4. If deltas cycle through a small set of values, classify as cyclic.
//  5. Otherwise classify as random (unpredictable) — port prediction is
//     abandoned for this NAT.
func AnalyzePortSequence(samples []PortSample) PortPrediction {
	if len(samples) < 2 {
		return PortPrediction{
			Pattern: PatternInsufficient,
			Samples: samples,
		}
	}

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Timestamp.Before(samples[j].Timestamp)
	})

	deltas := make([]int, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		deltas = append(deltas, samples[i].Port-samples[i-1].Port)
	}

	meanDelta := mean(deltas)
	variance := varianceInt(deltas, meanDelta)

	pp := PortPrediction{
		Samples: samples,
		Deltas:  deltas,
	}

	// Linear: low variance relative to mean delta.
	meanDeltaInt := int(meanDelta)
	if meanDeltaInt != 0 && variance < float64(absInt(meanDeltaInt))*float64(absInt(meanDeltaInt)) {
		pp.Pattern = PatternLinear
		pp.NextPort = samples[len(samples)-1].Port + meanDeltaInt
		// Window: ±2 deltas to cover minor deviations, capped at [1, 65535].
		halfW := absInt(meanDeltaInt) * 2
		pp.WindowStart = clampPort(pp.NextPort - halfW)
		pp.WindowEnd = clampPort(pp.NextPort + halfW)
		return pp
	}

	// Cyclic: deltas repeat (e.g., [5, 5, 5] is linear, but [3, 7, 3, 7] is cyclic).
	if isCyclic(deltas) {
		pp.Pattern = PatternCyclic
		nextDelta := deltas[len(deltas)%len(deltas)]
		pp.NextPort = samples[len(samples)-1].Port + nextDelta
		halfW := absInt(nextDelta)
		pp.WindowStart = clampPort(pp.NextPort - halfW)
		pp.WindowEnd = clampPort(pp.NextPort + halfW)
		return pp
	}

	// Random: no exploitable pattern.
	pp.Pattern = PatternRandom
	return pp
}

func mean(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return float64(sum) / float64(len(xs))
}

func varianceInt(xs []int, m float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		d := float64(x) - m
		sum += d * d
	}
	return sum / float64(len(xs))
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func clampPort(p int) int {
	if p < 1 {
		return 1
	}
	if p > 65535 {
		return 65535
	}
	return p
}

func isCyclic(deltas []int) bool {
	if len(deltas) < 4 {
		return false
	}
	// Check if the sequence has a period of 2.
	for i := 2; i < len(deltas); i++ {
		if deltas[i] != deltas[i-2] {
			return false
		}
	}
	return true
}
