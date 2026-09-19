package main

import (
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// TestCacheOptions pins the manager cache scope: the kinds the reconciler reads back only as
// link children are cached under the link component label, and they are the only scoped kinds.
func TestCacheOptions(t *testing.T) {
	linkSelector := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/component": "link"})

	tests := []struct {
		kind string
		want cache.ByObject
	}{
		{kind: "*v1.ServiceAccount", want: cache.ByObject{Label: linkSelector}},
		{kind: "*v1.Role", want: cache.ByObject{Label: linkSelector}},
		{kind: "*v1.RoleBinding", want: cache.ByObject{Label: linkSelector}},
		{kind: "*v1.ClusterRoleBinding", want: cache.ByObject{Label: linkSelector}},
	}

	want := make(map[string]cache.ByObject, len(tests))
	for _, tt := range tests {
		want[tt.kind] = tt.want
	}

	got := make(map[string]cache.ByObject, len(tests))
	for obj, byObject := range cacheOptions().ByObject {
		got[fmt.Sprintf("%T", obj)] = byObject
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("cache ByObject = %v, want exactly %v", got, want)
	}
}
