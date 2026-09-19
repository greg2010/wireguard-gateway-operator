package controller

import (
	corev1 "k8s.io/api/core/v1"
)

// resourceRequirementsEqual compares two ResourceRequirements by their quantities' canonical
// string form, since resource.Quantity carries an unexported cached representation.
func resourceRequirementsEqual(a, b corev1.ResourceRequirements) bool {
	return resourceListEqual(a.Requests, b.Requests) && resourceListEqual(a.Limits, b.Limits)
}

func resourceListEqual(a, b corev1.ResourceList) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok || v.String() != bv.String() {
			return false
		}
	}
	return true
}
