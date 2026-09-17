package maas

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/stretchr/testify/require"
)

func evalUnmeteredCEL(t *testing.T, expression string, input map[string]any) any {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("auth", cel.DynType), cel.Variable("request", cel.DynType), ext.Strings())
	require.NoError(t, err)
	ast, issues := env.Compile(expression)
	require.NoError(t, issues.Err(), expression)
	program, err := env.Program(ast)
	require.NoError(t, err)
	result, _, err := program.Eval(input)
	require.NoError(t, err, expression)
	return result.Value()
}

// unmeteredPolicyValue reports malformed generated policy shapes as test failures.
func unmeteredPolicyValue[T any](t *testing.T, value any, path ...any) T {
	t.Helper()
	for _, key := range path {
		switch k := key.(type) {
		case string:
			object, ok := value.(map[string]any)
			require.True(t, ok, "expected object at %v", key)
			value = object[k]
		case int:
			items, ok := value.([]any)
			require.True(t, ok, "expected array at %v", key)
			require.Less(t, k, len(items))
			value = items[k]
		default:
			t.Fatalf("unsupported policy path key %v", key)
		}
	}
	result, ok := value.(T)
	require.True(t, ok, "unexpected policy value type %T at %v", value, path)
	return result
}

func unmeteredTestRules(t *testing.T) map[string]any {
	t.Helper()
	r := &MaaSAuthPolicyReconciler{}
	spec := r.buildGatewayAuthPolicySpec(&oidcConfig{}, true, "", "tenant", "gateway-ns", "gateway")
	return unmeteredPolicyValue[map[string]any](t, spec, "defaults", "rules")
}

func TestUnmeteredAuthorizationBranchesAreANDSafe(t *testing.T) {
	rules := unmeteredTestRules(t)
	authorization := unmeteredPolicyValue[map[string]any](t, rules, "authorization")
	for _, tc := range []struct {
		name         string
		identity     any
		mode         bool
		wantIdentity bool
	}{
		{"first unmetered service", map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "system:serviceaccount:team-a:worker"}}, true, true},
		{"second unmetered service", map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "system:serviceaccount:team-b:other-worker"}}, true, true},
		{"ordinary service account", map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "system:serviceaccount:team-a:worker"}}, false, true},
		{"API key spoofing mode", "sk-oai-secret", true, false},
		{"ordinary API key", "sk-oai-secret", false, false},
		{"OIDC with forged user claim", map[string]any{"maas_authentication": "oidc", "user": map[string]any{"username": "system:serviceaccount:team-a:worker"}}, true, false},
		{"Kubernetes human", map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "alice"}}, true, false},
		{"missing provenance", map[string]any{"user": map[string]any{"username": "system:serviceaccount:team-a:worker"}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]any{}
			if tc.mode {
				headers["x-maas-invocation-mode"] = "unmetered"
			}
			input := map[string]any{"auth": map[string]any{"identity": tc.identity},
				"request": map[string]any{"path": "/models/safety/v1/chat/completions", "headers": headers}}
			for _, name := range []string{"unmetered-identity-valid", "unmetered-context-valid", unmeteredSARAuthorization} {
				rule := unmeteredPolicyValue[map[string]any](t, authorization, name)
				when := unmeteredPolicyValue[string](t, rule, "when", 0, "predicate")
				require.Equal(t, tc.mode, evalUnmeteredCEL(t, when, input), name)
			}
			membership := unmeteredPolicyValue[string](t, authorization, "require-group-membership", "when", 0, "predicate")
			require.Equal(t, !tc.mode, evalUnmeteredCEL(t, membership, input))
			validity := unmeteredPolicyValue[string](t, authorization, "subscription-valid", "when", 0, "predicate")
			require.Equal(t, !tc.mode, evalUnmeteredCEL(t, validity, input), "unmetered access must not require a subscription")
			require.Equal(t, tc.wantIdentity, evalUnmeteredCEL(t, celUnmeteredIdentity, input))
		})
	}
	sar := unmeteredPolicyValue[map[string]any](t, authorization, unmeteredSARAuthorization)
	require.Equal(t, int64(1), sar["priority"])
	for _, name := range []string{"unmetered-identity-valid", "unmetered-context-valid", "subscription-valid"} {
		require.Equal(t, int64(0), unmeteredPolicyValue[map[string]any](t, authorization, name)["priority"])
	}
	attrs := unmeteredPolicyValue[map[string]any](t, sar, "kubernetesSubjectAccessReview", "resourceAttributes")
	require.Equal(t, "models", unmeteredPolicyValue[string](t, attrs, "resource", "value"))
	require.Equal(t, "invoke-unmetered", unmeteredPolicyValue[string](t, attrs, "verb", "value"))
	authentication := unmeteredPolicyValue[map[string]any](t, rules, "authentication")
	for name, want := range map[string]string{"openshift-identities": "kubernetes", "oidc-identities": "oidc"} {
		require.Equal(t, want, unmeteredPolicyValue[string](t, authentication, name, "overrides", "maas_authentication", "value"))
	}
}

func TestUnmeteredExemptionRequiresSuccessfulSAR(t *testing.T) {
	rules := unmeteredTestRules(t)
	properties := unmeteredPolicyValue[map[string]any](t, rules, "response", "success", "filters", "identity", "json", "properties")
	expression := unmeteredPolicyValue[string](t, properties, "unmetered", "expression")
	const pair = "tenant/gold@models/safety"
	for _, tc := range []struct {
		name     string
		decision map[string]any
		want     bool
	}{
		{"allowed", map[string]any{"unmetered-sar": true}, true},
		{"denied", map[string]any{"unmetered-sar": false}, false},
		{"skipped", map[string]any{}, false},
		{"error", map[string]any{"unmetered-sar": nil}, false},
		{"missing authorization", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := map[string]any{
				"identity": map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "system:serviceaccount:team-a:worker"}},
				"metadata": map[string]any{},
			}
			if tc.decision != nil {
				auth["authorization"] = tc.decision
			}
			input := map[string]any{"auth": auth, "request": map[string]any{"path": "/models/safety/v1/chat/completions",
				"headers": map[string]any{"x-maas-invocation-mode": "unmetered", "x-maas-unmetered": "true"}}}
			require.Equal(t, tc.want, evalUnmeteredCEL(t, expression, input))
		})
	}
	for _, exemption := range []bool{false, true} {
		input := map[string]any{"auth": map[string]any{"identity": map[string]any{
			"selected_subscription_key": pair, "unmetered": exemption}},
			"request": map[string]any{"path": "/models/safety/v1/chat/completions"}}
		require.Equal(t, !exemption, evalUnmeteredCEL(t, subscriptionTokenLimitPredicate(pair), input))
	}
	input := map[string]any{"auth": map[string]any{"identity": map[string]any{"selected_subscription_key": pair}},
		"request": map[string]any{"path": "/models/safety/v1/chat/completions", "headers": map[string]any{"x-maas-unmetered": "true"}}}
	require.Equal(t, true, evalUnmeteredCEL(t, subscriptionTokenLimitPredicate(pair), input), "missing trusted exemption must count tokens")
}

func TestUnmeteredSkipsSubscription(t *testing.T) {
	rules := unmeteredTestRules(t)
	input := map[string]any{
		"auth": map[string]any{
			"metadata": map[string]any{},
			"identity": map[string]any{"maas_authentication": "kubernetes", "user": map[string]any{"username": "system:serviceaccount:services:runner", "groups": []string{}}},
		},
		"request": map[string]any{"path": "/v1/chat/completions", "headers": map[string]any{
			"x-gateway-model-name": "alias", "x-maas-invocation-mode": "unmetered",
		}},
	}
	when := unmeteredPolicyValue[string](t, rules, "metadata", "subscription-info", "when", 0, "predicate")
	require.Equal(t, false, evalUnmeteredCEL(t, when, input))
	require.NotContains(t, rules["metadata"], "unmetered-model", "no model resolver endpoint is needed")
	properties := unmeteredPolicyValue[map[string]any](t, rules, "response", "success", "filters", "identity", "json", "properties")
	for _, name := range []string{"selected_subscription", "selected_subscription_key", "subscription_error", "subscription_error_message"} {
		expression := unmeteredPolicyValue[string](t, properties, name, "expression")
		require.Equal(t, "", evalUnmeteredCEL(t, expression, input), "missing subscription metadata must not break response shaping")
	}
}

func TestUnmeteredSARCacheTTL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authz    int64
		metadata int64
		want     int64
	}{
		{"authorization TTL", 30, 60, 30},
		{"capped by metadata", 60, 20, 20},
		{"authorization cache disabled", 0, 60, 0},
		{"metadata cache disabled", 60, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &MaaSAuthPolicyReconciler{AuthzCacheTTL: tc.authz, MetadataCacheTTL: tc.metadata}
			spec := r.buildGatewayAuthPolicySpec(nil, false, "", "tenant", "gateway-ns", "gateway")
			ttl := unmeteredPolicyValue[int64](t, spec, "defaults", "rules", "authorization", unmeteredSARAuthorization, "cache", "ttl")
			require.Equal(t, tc.want, ttl)
		})
	}
}

func TestUnmeteredSARUsesPolicyNamespaceAndRoutingIdentity(t *testing.T) {
	keyFor := func(username, namespace, path, header string) any {
		r := &MaaSAuthPolicyReconciler{}
		spec := r.buildGatewayAuthPolicySpec(nil, false, "different-tenant-id", namespace, "gateway-ns", "gateway")
		sar := unmeteredPolicyValue[map[string]any](t, spec, "defaults", "rules", "authorization", unmeteredSARAuthorization)
		require.Equal(t, namespace, unmeteredPolicyValue[string](t, sar, "kubernetesSubjectAccessReview", "resourceAttributes", "namespace", "value"))
		expression := unmeteredPolicyValue[string](t, sar, "cache", "key", "selector")
		input := map[string]any{
			"auth":    map[string]any{"identity": map[string]any{"user": map[string]any{"username": username}}},
			"request": map[string]any{"path": path, "headers": map[string]any{"x-gateway-model-name": header, "x-maas-subscription": "spoofed/ignored"}},
		}
		name := unmeteredPolicyValue[string](t, sar, "kubernetesSubjectAccessReview", "resourceAttributes", "name", "expression")
		if path == "/v1/chat/completions" {
			require.Equal(t, header, evalUnmeteredCEL(t, name, input))
		} else {
			require.Equal(t, "safety", evalUnmeteredCEL(t, name, input))
		}
		return evalUnmeteredCEL(t, expression, input)
	}
	const caller = "system:serviceaccount:services:runner"
	const path = "/models/safety/v1/chat/completions"
	base := keyFor(caller, "policy-namespace", path, "")
	require.Equal(t, base, keyFor(caller, "policy-namespace", path, "irrelevant-header"))
	require.NotEqual(t, base, keyFor("system:serviceaccount:other:runner", "policy-namespace", path, ""))
	require.NotEqual(t, base, keyFor(caller, "other-policy-namespace", path, ""))
	require.NotEqual(t, base, keyFor(caller, "policy-namespace", "/other-models/safety/v1/chat/completions", ""))
	require.NotEqual(t, keyFor(caller, "policy-namespace", "/v1/chat/completions", "model-a"),
		keyFor(caller, "policy-namespace", "/v1/chat/completions", "model-b"))
}
