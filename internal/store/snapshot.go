package store

type Snapshot struct {
	Alerts           map[string]Alert
	Cases            map[string]Case
	Evidence         map[string]Evidence
	Decisions        map[string]Decision
	Tasks            map[string]Task
	Retests          map[string]Retest
	Events           []Event
	Batches          map[string]Batch
	ThresholdCatalog []any
	Idempotency      map[string]any
}
