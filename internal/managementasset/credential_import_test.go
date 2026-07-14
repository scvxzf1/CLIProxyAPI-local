package managementasset

import (
	"bytes"
	"testing"
)

func TestCredentialImportHTMLIsEmbedded(t *testing.T) {
	page := CredentialImportHTML()
	for _, marker := range [][]byte{
		[]byte("凭证导入"),
		[]byte("credential-import/execute"),
		[]byte("自动刷新与额度探测"),
		[]byte("搜索文件名、状态或探测详情"),
		[]byte("result-page-number"),
		[]byte("查看探测结果"),
		[]byte("result-plan-filter"),
		[]byte("credential_type"),
	} {
		if !bytes.Contains(page, marker) {
			t.Fatalf("embedded credential import page missing %q", marker)
		}
	}
}
