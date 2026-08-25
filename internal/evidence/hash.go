package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func Hash(i Input) string {
	refs := append([]string(nil), i.PhotoRefs...)
	sortStrings(refs)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%.4f|%.4f|%d|%s|%s", i.Checkpoint, strings.Join(refs, ","), i.Resample.PeakAmplitude, i.Resample.DominantFrequency, i.Resample.DurationMS, i.Notes, i.SubmittedBy)
	return hex.EncodeToString(h.Sum(nil))
}

func ChainHash(prev string, i Input) string { return HashWithPrev(prev, Hash(i)) }

func HashWithPrev(prev, current string) string {
	h := sha256.Sum256([]byte(prev + "|" + current))
	return hex.EncodeToString(h[:])
}

func sortStrings(a []string) {
	for i := range a {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
