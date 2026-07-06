package kubernetes

import rego.v1

ecr_sha := "533267178572.dkr.ecr.us-east-1.amazonaws.com/crypto-ecr-repo:27d0b1810b2fdde4c96da54bc7cd99f59fa78d2b"

test_allow_pinned_ecr if {
	obj := {"kind": "Deployment", "metadata": {"name": "api"}, "spec": {"template": {"spec": {"containers": [{"image": ecr_sha}]}}}}
	count(deny) == 0 with input as obj
	count(warn) == 0 with input as obj
}

test_deny_latest if {
	img := "533267178572.dkr.ecr.us-east-1.amazonaws.com/crypto-ecr-repo:latest"
	deny with input as {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"image": img}]}}}}
}

test_deny_untagged if {
	deny with input as {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"image": "nginx"}]}}}}
}

test_deny_privileged if {
	deny with input as {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"image": ecr_sha, "securityContext": {"privileged": true}}]}}}}
}

test_deny_hostnetwork if {
	deny with input as {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"hostNetwork": true, "containers": [{"image": ecr_sha}]}}}}
}

test_allow_argocd_application if {
	obj := {"kind": "Application", "metadata": {"name": "crypto-app"}, "spec": {"source": {"path": "eks-chart"}}}
	count(deny) == 0 with input as obj
	count(warn) == 0 with input as obj
}

test_allow_test_hook if {
	obj := {
		"kind": "Pod",
		"metadata": {"name": "test-connection", "annotations": {"helm.sh/hook": "test"}},
		"spec": {"containers": [{"image": "busybox:1.36"}]},
	}
	count(deny) == 0 with input as obj
	count(warn) == 0 with input as obj
}

test_warn_unapproved_registry if {
	obj := {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"image": "docker.io/library/redis:7"}]}}}}
	warn with input as obj
	count(deny) == 0 with input as obj
}
