package k8s

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDeploymentRolledOut(t *testing.T) {
	two := int32(2)

	tests := []struct {
		name           string
		spec           *int32
		generation     int64
		observed       int64
		replicas       int32
		updated        int32
		available      int32
		progressReason string
		progressStatus corev1.ConditionStatus
		want           bool
		wantErr        bool
	}{
		{
			name: "complete", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 2,
			want: true,
		},
		{
			name: "progressing with new replica set available", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 2,
			progressReason: "NewReplicaSetAvailable", progressStatus: corev1.ConditionTrue,
			want: true, wantErr: false,
		},
		{
			name: "generation not observed", spec: &two,
			generation: 3, observed: 2, replicas: 2, updated: 2, available: 2,
			want: false,
		},
		{
			name: "surge pod mid-rollout", spec: &two,
			generation: 2, observed: 2, replicas: 3, updated: 1, available: 2,
			want: false,
		},
		{
			name: "old pod still counted", spec: &two,
			generation: 2, observed: 2, replicas: 3, updated: 2, available: 3,
			want: false,
		},
		{
			name: "updated pod not available", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 1,
			want: false,
		},
		{
			name: "nil spec replicas", spec: nil,
			generation: 1, observed: 1, replicas: 1, updated: 1, available: 1,
			want: true,
		},
		{
			name: "progress deadline exceeded", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 1, available: 1,
			progressReason: "ProgressDeadlineExceeded", progressStatus: corev1.ConditionFalse,
			want: false, wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "link", Generation: tt.generation},
				Spec:       appsv1.DeploymentSpec{Replicas: tt.spec},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: tt.observed,
					Replicas:           tt.replicas,
					UpdatedReplicas:    tt.updated,
					AvailableReplicas:  tt.available,
				},
			}
			if tt.progressReason != "" {
				dep.Status.Conditions = append(dep.Status.Conditions, appsv1.DeploymentCondition{
					Type:   appsv1.DeploymentProgressing,
					Status: tt.progressStatus,
					Reason: tt.progressReason,
				})
			}

			got, err := deploymentRolledOut(dep)
			if got != tt.want {
				t.Errorf("deploymentRolledOut() got = %v, want %v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("deploymentRolledOut() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
