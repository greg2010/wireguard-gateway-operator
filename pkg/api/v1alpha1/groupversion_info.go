// Package v1alpha1 contains the Gateway user-facing API for wgnet.dev.
// +kubebuilder:object:generate=true
// +groupName=wgnet.dev
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion = schema.GroupVersion{Group: "wgnet.dev", Version: "v1alpha1"}

	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &Gateway{}, &GatewayList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
