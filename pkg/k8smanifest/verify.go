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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	k8smnfcosign "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/cosign"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
)

var EmbeddedAnnotationMaskKeys = []string{
	fmt.Sprintf("metadata.annotations.\"%s\"", ImageRefAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", BundleAnnotationKey),
}

type SignatureVerifier interface {
	Verify(pubkeyPath *string) (bool, string, error)
}

func NewSignatureVerifier(objYAMLBytes []byte, imageRef string) SignatureVerifier {
	var annotations map[string]string
	if imageRef == "" {
		annotations = k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
		if annoImageRef, ok := annotations[ImageRefAnnotationKey]; ok {
			imageRef = annoImageRef
		}
	}
	if imageRef == "" {
		return &AnnotationSignatureVerifier{annotations: annotations}
	} else {
		return &ImageSignatureVerifier{imageRef: imageRef}
	}
}

type ImageSignatureVerifier struct {
	imageRef string
	useCache bool
	cacheDir string
}

func (v *ImageSignatureVerifier) Verify(pubkeyPath *string) (bool, string, error) {
	imageRef := v.imageRef
	if imageRef == "" {
		return false, "", errors.New("no image reference is found")
	}

	return k8smnfcosign.VerifyImage(imageRef, pubkeyPath)
}

type AnnotationSignatureVerifier struct {
	annotations map[string]string
}

func (v *AnnotationSignatureVerifier) Verify(pubkeyPath *string) (bool, string, error) {
	annotations := v.annotations

	msg, ok := annotations[MessageAnnotationKey]
	if !ok {
		return false, "", fmt.Errorf("`%s` is not found in the annotations", MessageAnnotationKey)
	}
	sig, ok := annotations[SignatureAnnotationKey]
	if !ok {
		return false, "", fmt.Errorf("`%s` is not found in the annotations", SignatureAnnotationKey)
	}
	cert, _ := annotations[CertificateAnnotationKey]

	msgBytes := []byte(msg)
	sigBytes := []byte(sig)
	certBytes := []byte(cert)

	return k8smnfcosign.VerifyBlob(msgBytes, sigBytes, certBytes, pubkeyPath)
}

// This is an interface for fetching YAML manifest
// a function Fetch() fetches a YAML manifest which matches the input object's kind, name and so on
type ManifestFetcher interface {
	Fetch(objYAMLBytes []byte) ([]byte, bool, error)
}

func NewManifestFetcher(imageRef string) ManifestFetcher {
	if imageRef == "" {
		return &AnnotationManifestFetcher{}
	} else {
		return &ImageManifestFetcher{imageRef: imageRef}
	}
}

// ImageManifestFetcher is a fetcher implementation for image reference
type ImageManifestFetcher struct {
	imageRef string
	useCache bool
	cacheDir string
}

func (f *ImageManifestFetcher) Fetch(objYAMLBytes []byte) ([]byte, bool, error) {
	imageRef := f.imageRef
	if imageRef == "" {
		annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
		if annoImageRef, ok := annotations[ImageRefAnnotationKey]; ok {
			imageRef = annoImageRef
		}
	}
	if imageRef == "" {
		return nil, false, errors.New("no image reference is found")
	}

	image, err := k8smnfutil.PullImage(imageRef)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to pull image")
	}

	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to get YAMLs in the image")
	}

	found, foundManifest := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes)
	if !found {
		return nil, false, errors.New("failed to find a YAML manifest in the image")
	}
	return foundManifest, true, nil
}

type AnnotationManifestFetcher struct {
}

func (f *AnnotationManifestFetcher) Fetch(objYAMLBytes []byte) ([]byte, bool, error) {

	annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)

	base64Msg, messageFound := annotations[MessageAnnotationKey]
	if !messageFound {
		return nil, false, nil
	}
	gzipMsg, err := base64.StdEncoding.DecodeString(base64Msg)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to decode base64 message in the annotation")
	}

	gzipStream := bytes.NewBuffer(gzipMsg)
	yamls, err := k8smnfutil.GetYAMLsInArtifact(gzipStream)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to read YAMLs in the gzipped message")
	}

	concatYAMLbytes := k8smnfutil.ConcatenateYAMLs(yamls)

	found, foundManifest := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes)
	if !found {
		return nil, false, errors.New("failed to find a YAML manifest in the gzipped message")
	}
	return foundManifest, true, nil
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
