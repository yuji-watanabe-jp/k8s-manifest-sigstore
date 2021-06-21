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
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
)

var EmbeddedAnnotationMaskKeys = []string{
	fmt.Sprintf("metadata.annotations.\"%s\"", ImageRefAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", BundleAnnotationKey),
}

type VerifyResult struct {
	Verified bool                `json:"verified"`
	Signer   string              `json:"signer"`
	Diff     *mapnode.DiffResult `json:"diff"`
}

func (r *VerifyResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}

func Verify(manifest []byte, imageRef, keyPath string, useCache bool, cacheDir string) (*VerifyResult, error) {
	if manifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}

	verified := false
	signerName := ""

	// TODO: support directly attached annotation sigantures
	if imageRef != "" {
		fetcher := ImageManifestFetcher{}
		if useCache && cacheDir != "" {
			fetcher.UseCache = useCache
			fetcher.CacheDir = cacheDir
		}
		manifestInImage, err := fetcher.FetchYAMLManifest(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch YAML manifest")
		}

		ok, tmpDiff, err := matchManifest(manifest, manifestInImage)
		if err != nil {
			return nil, errors.Wrap(err, "failed to match manifest")
		}
		if !ok {
			return &VerifyResult{
				Verified: false,
				Signer:   "",
				Diff:     tmpDiff,
			}, nil
		}

		verifier := ImageSignatureVerifier{}
		if useCache && cacheDir != "" {
			verifier.UseCache = useCache
			verifier.CacheDir = cacheDir
		}
		verified, signerName, err = verifier.Verify(imageRef, &keyPath)
		if err != nil {
			return nil, errors.Wrap(err, "error occured during signature verification")
		}
	}

	return &VerifyResult{
		Verified: verified,
		Signer:   signerName,
	}, nil

}

func matchManifest(manifest, manifestInImage []byte) (bool, *mapnode.DiffResult, error) {
	log.Debug("manifest:", string(manifest))
	log.Debug("manifest in image:", string(manifestInImage))
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
	found, foundBytes := k8ssigutil.FindSingleYaml(manifestInImage, apiVersion, kind, name, namespace)
	if !found {
		return false, nil, errors.New("failed to find the input file in image")
	}
	manifestNode, err := mapnode.NewFromYamlBytes(foundBytes)
	if err != nil {
		return false, nil, err
	}
	maskedManifestNode := manifestNode.Mask(EmbeddedAnnotationMaskKeys)
	diff := maskedInputNode.Diff(maskedManifestNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}
