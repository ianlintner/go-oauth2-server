package oauth

import "testing"

func TestApprovalCovers(t *testing.T) {
	a := Approval{Scopes: []string{"openid", "read"}}
	for _, tc := range []struct {
		req  string
		want bool
	}{
		{"", true}, {"read", true}, {"read openid", true}, {"write", false}, {"read write", false},
	} {
		if got := a.Covers(tc.req); got != tc.want {
			t.Errorf("Covers(%q) = %v, want %v", tc.req, got, tc.want)
		}
	}
	if (Approval{}).Covers("read") {
		t.Error("an approval with no scopes covered a scope")
	}
}
