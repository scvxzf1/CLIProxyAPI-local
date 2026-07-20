package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

const invalidXAIGrokCLICredentialMessage = "status_code=401, Invalid or expired credentials (auth_kind=bearer, x_xai_token_auth=xai-grok-cli, upstream=PermissionDenied, reason=no auth context)"

type invalidXAICredentialStore struct {
	mu      sync.Mutex
	items   map[string]*Auth
	deleted []string
}

func (s *invalidXAICredentialStore) List(context.Context) ([]*Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Auth, 0, len(s.items))
	for _, auth := range s.items {
		out = append(out, auth.Clone())
	}
	return out, nil
}

func (s *invalidXAICredentialStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]*Auth)
	}
	s.items[auth.ID] = auth.Clone()
	return auth.ID, nil
}

func (s *invalidXAICredentialStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, id)
	return nil
}

func (s *invalidXAICredentialStore) deletedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deleted...)
}

func TestManagerMarkResultDeletesInvalidXAIGrokCLICredential(t *testing.T) {
	ctx := context.Background()
	store := &invalidXAICredentialStore{}
	manager := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "xai-invalid.json",
		Provider: "xai",
		FileName: "xai-invalid.json",
		Metadata: map[string]any{"type": "xai", "access_token": "secret"},
		Attributes: map[string]string{
			AttributePath:     "/tmp/xai-invalid.json",
			AttributeAuthKind: AuthKindOAuth,
		},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "grok-4.5",
		Error: &Error{
			Message:    invalidXAIGrokCLICredentialMessage,
			HTTPStatus: 0,
		},
	})

	if _, ok := manager.GetByID(auth.ID); ok {
		t.Fatalf("invalid auth %q remained in runtime", auth.ID)
	}
	deleted := store.deletedIDs()
	if len(deleted) != 1 || deleted[0] != auth.FileName {
		t.Fatalf("Delete() IDs = %v, want [%q]", deleted, auth.FileName)
	}
}

func TestDeleteInvalidXAIGrokCLICredentialKeepsRefreshedCredential(t *testing.T) {
	ctx := context.Background()
	store := &invalidXAICredentialStore{}
	manager := NewManager(store, nil, nil)
	stale := &Auth{
		ID:       "xai-refreshed.json",
		Provider: "xai",
		FileName: "xai-refreshed.json",
		Metadata: map[string]any{"type": "xai", "access_token": "stale-token"},
	}
	if _, errRegister := manager.Register(ctx, stale); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	refreshed := stale.Clone()
	refreshed.Metadata["access_token"] = "fresh-token"
	if _, errUpdate := manager.Update(ctx, refreshed); errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}

	manager.deleteInvalidXAIGrokCLICredential(ctx, stale)

	current, ok := manager.GetByID(stale.ID)
	if !ok || current == nil {
		t.Fatalf("refreshed auth %q was removed", stale.ID)
	}
	if got := authMetadataString(current, "access_token"); got != "fresh-token" {
		t.Fatalf("access_token = %q, want fresh-token", got)
	}
	if deleted := store.deletedIDs(); len(deleted) != 0 {
		t.Fatalf("Delete() IDs = %v, want none", deleted)
	}
}

func TestManagerMarkResultKeepsOtherUnauthorizedCredentials(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		message  string
		status   int
	}{
		{
			name:     "ordinary xai unauthorized",
			provider: "xai",
			message:  "unauthorized",
			status:   http.StatusUnauthorized,
		},
		{
			name:     "different provider",
			provider: "codex",
			message:  invalidXAIGrokCLICredentialMessage,
			status:   http.StatusUnauthorized,
		},
		{
			name:     "different status",
			provider: "xai",
			message:  invalidXAIGrokCLICredentialMessage,
			status:   http.StatusForbidden,
		},
		{
			name:     "missing no auth context reason",
			provider: "xai",
			message:  "Invalid or expired credentials (auth_kind=bearer, x_xai_token_auth=xai-grok-cli, upstream=PermissionDenied)",
			status:   http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := &invalidXAICredentialStore{}
			manager := NewManager(store, nil, nil)
			auth := &Auth{
				ID:       "keep-auth.json",
				Provider: tt.provider,
				FileName: "keep-auth.json",
				Metadata: map[string]any{"type": tt.provider, "access_token": "secret"},
			}
			if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
				t.Fatalf("Register() error = %v", errRegister)
			}

			manager.MarkResult(ctx, Result{
				AuthID:   auth.ID,
				Provider: auth.Provider,
				Model:    "model",
				Error:    &Error{Message: tt.message, HTTPStatus: tt.status},
			})

			if _, ok := manager.GetByID(auth.ID); !ok {
				t.Fatalf("auth %q was unexpectedly removed", auth.ID)
			}
			if deleted := store.deletedIDs(); len(deleted) != 0 {
				t.Fatalf("Delete() IDs = %v, want none", deleted)
			}
		})
	}
}
