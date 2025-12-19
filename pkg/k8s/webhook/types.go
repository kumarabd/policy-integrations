package webhook

import (
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SubjectAccessReview wraps the official Kubernetes SubjectAccessReview type
// with additional metadata for request/response handling.
type SubjectAccessReview struct {
	metav1.TypeMeta `json:",inline"`
	Spec            authzv1.SubjectAccessReviewSpec   `json:"spec"`
	Status          *authzv1.SubjectAccessReviewStatus `json:"status,omitempty"`
}

