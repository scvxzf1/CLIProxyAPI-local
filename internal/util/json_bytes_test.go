package util

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestMergeJSONArrayRaw_PreservesLargeItemBytes(t *testing.T) {
	imageURL := "data:image/png;base64," + strings.Repeat("A", 1024)
	image := `{"type":"input_image","image_url":"` + imageURL + `"}`
	existing := `[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},` + image + `]`
	appendRaw := `[{"type":"message","role":"user","content":[{"type":"input_text","text":"again"}]}]`

	merged, err := MergeJSONArrayRaw(existing, appendRaw)
	if err != nil {
		t.Fatalf("MergeJSONArrayRaw() error = %v", err)
	}
	if !strings.Contains(merged, strings.Repeat("A", 1024)) {
		t.Fatal("expected original base64 bytes to be preserved")
	}
	if got := len(gjson.Parse(merged).Array()); got != 3 {
		t.Fatalf("merged len = %d, want 3", got)
	}
}

func TestSetJSONBytes_UpdatesExistingWithoutLosingBody(t *testing.T) {
	body := []byte(`{"model":"gpt-5","input":[{"type":"input_image","image_url":"data:image/png;base64,QQ=="}],"stream":false}`)
	updated := SetJSONBytes(body, "stream", true)
	if !gjson.GetBytes(updated, "stream").Bool() {
		t.Fatalf("stream = %v, want true", gjson.GetBytes(updated, "stream").Value())
	}
	if got := gjson.GetBytes(updated, "input.0.image_url").String(); got != "data:image/png;base64,QQ==" {
		t.Fatalf("image_url changed unexpectedly: %q", got)
	}
}

func TestDeleteJSONBytes_NoopWhenMissing(t *testing.T) {
	body := []byte(`{"model":"gpt-5"}`)
	updated := DeleteJSONBytes(body, "prompt_cache_retention")
	if string(updated) != string(body) {
		t.Fatalf("expected no-op delete to keep same bytes, got %s", updated)
	}
}

func TestJoinJSONRawMessages(t *testing.T) {
	out := JoinJSONRawMessages([][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"b":2}`),
	})
	if string(out) != `[{"a":1},{"b":2}]` {
		t.Fatalf("JoinJSONRawMessages() = %s", out)
	}
}
