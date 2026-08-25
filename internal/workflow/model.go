package workflow

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/store"
	"errors"
	"sync"
	"time"
)

var ErrConflict = errors.New("revision conflict")
var ErrInvalidTransition = errors.New("invalid transition")
var ErrClaimRequired = errors.New("案件由其他人员持有研判锁")

type Service struct {
	Store             *store.Store
	mu                sync.Mutex
	AssociationWindow time.Duration
	checkpointPlans   map[string][]store.CheckpointProgress
}

type AlertInput struct {
	AlertID, BridgeID, SensorID string
	CapturedAt                  time.Time
	ReceivedAt                  time.Time
	DriftTolerance              time.Duration
	DensityWindow               time.Duration
	assessment.Signal
}
