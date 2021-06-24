//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package k8smanifest

import (
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
)

func VerifyManifest(manifest []byte, vo *VerifyManifestOption) (*VerifyResult, error) {
	if manifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}

	var obj unstructured.Unstructured
	_ = yaml.Unmarshal(manifest, &obj)

	verified := false
	signerName := ""
	var err error

	// get ignore fields configuration for this resource if found
	ignoreFields := []string{}
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignoreFields = fields
		}
	}

	var manifestInRef []byte
	var manifestInRefFound bool
	manifestInRef, manifestInRefFound, err = NewManifestFetcher(vo.ImageRef).Fetch(manifest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch YAML manifest")
	}
	if !manifestInRefFound {
		return &VerifyResult{
			Verified: false,
		}, nil
	}

	matched, diff, err := matchManifest(manifest, manifestInRef, ignoreFields)
	if err != nil {
		return nil, errors.Wrap(err, "failed to match manifest")
	}
	if !matched {
		return &VerifyResult{
			Verified: false,
			Signer:   "",
			Diff:     diff,
		}, nil
	}

	var keyPath *string
	if vo.KeyPath != "" {
		keyPath = &(vo.KeyPath)
	}

	verified, signerName, err = NewSignatureVerifier(manifest, vo.ImageRef, keyPath).Verify()
	if err != nil {
		return nil, errors.Wrap(err, "error occured during signature verification")
	}
	if verified {
		if !vo.Signers.Match(signerName) {
			verified = false
		}
	}

	return &VerifyResult{
		Verified: verified,
		Signer:   signerName,
	}, nil
}

func matchManifest(manifest, manifestInRef []byte, ignoreFields []string) (bool, *mapnode.DiffResult, error) {
	log.Debug("manifest:", string(manifest))
	log.Debug("manifest in reference:", string(manifestInRef))
	inputFileNode, err := mapnode.NewFromYamlBytes(manifest)
	if err != nil {
		return false, nil, err
	}
	maskedInputNode := inputFileNode.Mask(EmbeddedAnnotationMaskKeys)

	var obj unstructured.Unstructured
	err = yaml.Unmarshal(manifest, &obj)
	if err != nil {
		return false, nil, err
	}
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()
	found, foundBytes := k8ssigutil.FindSingleYaml(manifestInRef, apiVersion, kind, name, namespace)
	if !found {
		return false, nil, errors.New("failed to find the YAML manifest")
	}
	manifestNode, err := mapnode.NewFromYamlBytes(foundBytes)
	if err != nil {
		return false, nil, err
	}
	maskedManifestNode := manifestNode.Mask(EmbeddedAnnotationMaskKeys)
	var matched bool
	diff := maskedInputNode.Diff(maskedManifestNode)

	// filter out ignoreFields
	if diff != nil && len(ignoreFields) > 0 {
		_, diff, _ = diff.Filter(ignoreFields)
	}
	if diff == nil || diff.Size() == 0 {
		matched = true
		diff = nil
	}
	return matched, diff, nil
}
