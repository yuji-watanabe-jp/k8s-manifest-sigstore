module github.com/IBM/k8s-sigstore

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/google/go-containerregistry v0.5.1
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.1.3
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.21.1
)

replace (
	github.com/IBM/k8s-sigstore => ./
	github.com/sigstore/cosign => github.com/sigstore/cosign v0.4.1-0.20210602105506-5cb21aa7fbf9

)
