package storesnapshotalias

import (
	"bridgewatch/internal/store"
	"testing"
)

func TestSnapshotMutationDoesNotRewriteStore(t *testing.T) {
	st := store.New("")
	st.PutCase(store.Case{CaseID: "case-1", Status: "pending_review"})
	snap := st.Snapshot()
	delete(snap.Cases, "case-1")
	if _, ok := st.GetCase("case-1"); !ok {
		t.Fatalf("snapshot mutation removed stored case")
	}
}
