package conventions

import (
	"fmt"
	"strings"
)

// ActionMode determines the action format.
type ActionMode string

const (
	// ActionModeSimple uses format "k8s.<verb>.<resource>"
	ActionModeSimple ActionMode = "simple"
	// ActionModeWithGroup uses format "k8s.<verb>.<group>.<resource>"
	ActionModeWithGroup ActionMode = "with_group"
)

// BuildResourceAction builds a Kubernetes resource action string.
// It matches the conventions used in the k8s mapper.
func BuildResourceAction(verb, group, resource, subresource string, mode ActionMode) string {
	verb = strings.ToLower(verb)
	
	var action string
	if mode == ActionModeWithGroup && group != "" {
		// Include API group
		if group == "" {
			group = "core"
		}
		action = fmt.Sprintf("k8s.%s.%s.%s", verb, group, resource)
	} else {
		// Simple format without group
		action = fmt.Sprintf("k8s.%s.%s", verb, resource)
	}
	
	// Append subresource if present
	if subresource != "" {
		action += "/" + subresource
	}
	
	return action
}

// BuildNonResourceAction builds a Kubernetes non-resource action string.
func BuildNonResourceAction(verb string) string {
	verb = strings.ToLower(verb)
	return fmt.Sprintf("k8s.%s.nonresource", verb)
}

// CommonKubernetesVerbs is a list of common Kubernetes verbs.
var CommonKubernetesVerbs = []string{
	"get",
	"list",
	"watch",
	"create",
	"update",
	"patch",
	"delete",
	"deletecollection",
	"impersonate",
	"bind",
	"escalate",
	"use",
}

// IsValidVerb checks if a verb is a valid Kubernetes verb.
func IsValidVerb(verb string) bool {
	verb = strings.ToLower(verb)
	for _, v := range CommonKubernetesVerbs {
		if v == verb {
			return true
		}
	}
	return false
}

// NormalizeVerb normalizes a verb to lowercase.
func NormalizeVerb(verb string) string {
	return strings.ToLower(verb)
}

