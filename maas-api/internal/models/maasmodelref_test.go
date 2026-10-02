package models_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/constant"
	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/models"
)

type modelRefLister struct {
	item *unstructured.Unstructured
}

func (l modelRefLister) List() ([]*unstructured.Unstructured, error) {
	return []*unstructured.Unstructured{nil, l.item}, nil
}

func TestListFromMaaSModelRefLister_AnnotationAllowlist(t *testing.T) {
	const regionsKey = "example.com/regions"
	tests := []struct {
		name               string
		kind               string
		allowlist          []string
		want               map[string]string
		withoutDisplayName bool
	}{
		{
			name:      "external ref exposes exact keys and preserves string values",
			kind:      "ExternalModel",
			allowlist: []string{regionsKey, "example.com/empty", "example.com/missing", regionsKey},
			want:      map[string]string{regionsKey: `["eu-west","us-east"]`, "example.com/empty": ""},
		},
		{name: "external ref exposes nothing by default", kind: "ExternalModel"},
		{name: "external ref with no matching keys", kind: "ExternalModel", allowlist: []string{"example.com/missing"}},
		{name: "allowlist does not match prefixes", kind: "ExternalModel", allowlist: []string{"example.com/region"}},
		{name: "LLMInferenceService ref exposes no annotations", kind: "LLMInferenceService", allowlist: []string{regionsKey}},
		{name: "llmisvc ref exposes no annotations", kind: "llmisvc", allowlist: []string{regionsKey}},
		{name: "default kind exposes no annotations", allowlist: []string{regionsKey}},
		{
			name:               "external ref with only allowlisted annotations includes modelDetails",
			kind:               "ExternalModel",
			allowlist:          []string{regionsKey},
			want:               map[string]string{regionsKey: `["eu-west","us-east"]`},
			withoutDisplayName: true,
		},
		{
			name:               "external ref with no matching annotations omits empty modelDetails",
			kind:               "ExternalModel",
			allowlist:          []string{"example.com/missing"},
			withoutDisplayName: true,
		},
		{
			name:               "llmisvc ref with only allowlisted annotations omits modelDetails",
			kind:               "llmisvc",
			allowlist:          []string{regionsKey},
			withoutDisplayName: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := &unstructured.Unstructured{Object: map[string]any{
				"spec":   map[string]any{"modelRef": map[string]any{"kind": tt.kind, "name": "upstream"}},
				"status": map[string]any{"phase": "Ready", "endpoint": "https://gateway.example.com"},
			}}
			ref.SetName("model-ref")
			ref.SetNamespace("test")
			annotations := map[string]string{
				regionsKey:                     `["eu-west","us-east"]`,
				"example.com/empty":            "",
				"example.com/private":          "internal-only",
				constant.AnnotationDisplayName: "Regional vLLM",
			}
			if tt.withoutDisplayName {
				delete(annotations, constant.AnnotationDisplayName)
			}
			ref.SetAnnotations(annotations)
			before := ref.DeepCopy()
			list, err := models.ListFromMaaSModelRefLister(modelRefLister{item: ref}, tt.allowlist...)
			require.NoError(t, err)
			require.Len(t, list, 1)
			wantDetails := !tt.withoutDisplayName || tt.want != nil
			if wantDetails {
				require.NotNil(t, list[0].Details)
				assert.Equal(t, tt.want, list[0].Details.Metadata)
				if !tt.withoutDisplayName {
					assert.Equal(t, "Regional vLLM", list[0].Details.DisplayName)
				}
			} else {
				assert.Nil(t, list[0].Details)
			}
			assert.Equal(t, "https://gateway.example.com", list[0].URL.String())
			assert.Equal(t, before, ref, "conversion must not modify cached objects")

			encoded, err := json.Marshal(list[0])
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			assert.NotContains(t, fields, "metadata")
			if wantDetails {
				var details map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(fields["modelDetails"], &details))
				if tt.want == nil {
					assert.NotContains(t, details, "metadata")
				} else {
					assert.Contains(t, details, "metadata")
				}
			} else {
				assert.NotContains(t, fields, "modelDetails")
			}
			if tt.want != nil {
				list[0].Details.Metadata[regionsKey] = "changed"
				assert.Equal(t, before, ref, "response annotations must not alias the cache")
			}
			var decoded models.Model
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			if wantDetails {
				require.NotNil(t, decoded.Details)
				assert.Equal(t, tt.want, decoded.Details.Metadata)
			} else {
				assert.Nil(t, decoded.Details)
			}
		})
	}
}
