package redisstore

import (
	"cmp"
	"context"
	"encoding/json"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

const (
	KeyArrivals = "iasg:arrivals"
	KeyHealth   = "iasg:telemetry:health"
)

// streamStore appends one kind of record to its own capped stream. Arrivals
// and the heartbeat differ only in the fields they index beside the payload.
//
// Deliberately does not touch iasg:stats or iasg:attackers. Those counters
// mean "requests the gateway finished handling", and incrementing them here
// would double every number the console shows.
type streamStore[T any] struct {
	client *redis.Client
	key    string
	maxLen int64
	values func(rec T, payload []byte) map[string]any
}

// ArrivalStore's indexed fields mirror the event stream's, so a consumer can
// filter either stream the same way without decoding the payload.
type ArrivalStore = streamStore[telemetry.Arrival]

// HealthStore is the telemetry heartbeat, capped far shorter than the request
// streams: it is one record a second, and history older than the capture run
// is of no use to anyone.
type HealthStore = streamStore[telemetry.Health]

// Arrivals shares the Store's connection pool. A second pool would mean a
// second set of connections competing for the same Redis under exactly the
// load where connections are scarce.
func (s *Store) Arrivals(cfg config.RedisConfig) *ArrivalStore {
	if s == nil || s.client == nil {
		return nil
	}
	key := cfg.ArrivalStreamKey
	key = cmp.Or(key, KeyArrivals)
	maxLen := cfg.ArrivalMaxLen
	if maxLen <= 0 {
		maxLen = s.maxLen
	}
	return &ArrivalStore{client: s.client, key: key, maxLen: maxLen,
		values: func(rec telemetry.Arrival, payload []byte) map[string]any {
			return map[string]any{"arrival": payload, "ip": rec.IP, "path": rec.Path, "requestId": rec.RequestID}
		}}
}

func (s *Store) Health(cfg config.RedisConfig) *HealthStore {
	if s == nil || s.client == nil {
		return nil
	}
	key := cfg.HealthStreamKey
	key = cmp.Or(key, KeyHealth)
	maxLen := cfg.HealthMaxLen
	if maxLen <= 0 {
		maxLen = 86400
	}
	return &HealthStore{client: s.client, key: key, maxLen: maxLen,
		values: func(rec telemetry.Health, payload []byte) map[string]any {
			return map[string]any{"health": payload, "seq": rec.Seq}
		}}
}

func (s *streamStore[T]) WriteEvent(ctx context.Context, rec T) error {
	if s == nil || s.client == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.client.XAdd(ctx, &redis.XAddArgs{
		Stream: s.key,
		MaxLen: s.maxLen,
		Approx: true,
		Values: s.values(rec, payload),
	}).Err()
}
