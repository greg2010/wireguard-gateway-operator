// Package v1alpha1 contains the Gateway user-facing API for wgnet.dev.
// +kubebuilder:object:generate=true
// +groupName=wgnet.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion = schema.GroupVersion{Group: "wgnet.dev", Version: "v1alpha1"}

	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	AddToScheme = SchemeBuilder.AddToScheme
)
