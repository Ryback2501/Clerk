package admin

import (
	"sync"
	"time"

	"github.com/Ryback2501/Clerk/internal/secret"
)

// revealTTL bounds how long an unread secret stays in memory.
const revealTTL = 5 * time.Minute

const revealTokenBytes = 32

// revealStore holds freshly generated client secrets just long enough to show
// them once.
//
// The alternatives are all worse: a redirect would put the secret in a URL and
// therefore in access logs and referrer headers; rendering it straight from the
// POST response would re-create the application on refresh; and persisting it
// would defeat the point of storing only a hash. Holding it in memory under a
// single-use token avoids all three. Losing these on restart is acceptable —
// the administrator can regenerate the secret.
type revealStore struct {
	mu      sync.Mutex
	entries map[string]revealEntry

	// now is injectable so expiry can be tested without sleeping.
	now func() time.Time
}

type revealEntry struct {
	applicationID int64
	secret        string
	expiresAt     time.Time
}

func newRevealStore() *revealStore {
	return &revealStore{
		entries: make(map[string]revealEntry),
		now:     time.Now,
	}
}

// put stores a secret for one application and returns the single-use token
// that retrieves it.
func (s *revealStore) put(applicationID int64, value string) string {
	token, err := secret.Token(revealTokenBytes)
	if err != nil {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	s.entries[token] = revealEntry{
		applicationID: applicationID,
		secret:        value,
		expiresAt:     s.now().Add(revealTTL),
	}
	return token
}

// take returns the secret for token and removes it, so a refresh cannot show
// the secret a second time.
//
// The secret is released only to the application it was generated for. A
// lookup from a different application is refused and, deliberately, does not
// consume the entry: navigating elsewhere must not destroy a secret that has
// not been shown yet.
func (s *revealStore) take(token string, applicationID int64) (string, bool) {
	if token == "" {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[token]
	if !ok {
		return "", false
	}
	if entry.applicationID != applicationID {
		return "", false
	}
	delete(s.entries, token)

	if s.now().After(entry.expiresAt) {
		return "", false
	}
	return entry.secret, true
}

// evictExpiredLocked drops timed-out entries. Called on write, which is often
// enough for a store that holds at most a handful of items.
func (s *revealStore) evictExpiredLocked() {
	now := s.now()
	for token, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, token)
		}
	}
}
