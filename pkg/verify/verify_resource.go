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

package verify

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/kubeutil"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
)

const defaultDryRunNamespace = "default"

func VerifyResource(objs []unstructured.Unstructured, imageRef, keyPath string) (*VerifyResult, error) {

	verified := false
	signerName := ""

	// TODO: support directly attached annotation sigantures
	if imageRef != "" {
		image, err := k8ssigutil.PullImage(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		for _, obj := range objs {
			ok, err := matchResourceWithManifest(obj, image)
			if err != nil {
				return nil, errors.Wrap(err, "failed to match resource with manifest")
			}
			if !ok {
				return nil, errors.New("failed to match resource with manifest")
			}
		}

		verified, signerName, err = imageVerify(imageRef, &keyPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify image")
		}
	}

	return &VerifyResult{
		Verfied: verified,
		Signer:  signerName,
	}, nil

}

func matchResourceWithManifest(obj unstructured.Unstructured, image v1.Image) (bool, error) {

	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()

	concatYAMLFromImage, err := k8ssigutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return false, err
	}
	fmt.Println("[DEBUG] obj: apiVersion", apiVersion, "kind", kind, "name", name)
	fmt.Println("[DEBUG] manifest in image:", string(concatYAMLFromImage))

	found, foundBytes := k8ssigutil.FindSingleYaml(concatYAMLFromImage, apiVersion, kind, name, namespace)
	if !found {
		return false, errors.New("failed to find the corresponding manifest YAML file in image")
	}

	var matched bool
	objBytes, _ := json.Marshal(obj.Object)

	// CASE1: direct match
	matched, err = directMatch(objBytes, foundBytes)
	if err != nil {
		return false, errors.Wrap(err, "error occured during diract match")
	}
	if matched {
		return true, nil
	}

	// CASE2: dryrun create match
	matched, err = dryrunCreateMatch(objBytes, foundBytes)
	if err != nil {
		return false, errors.Wrap(err, "error occured during dryrun create match")
	}
	if matched {
		return true, nil
	}

	// CASE3: dryrun apply match
	matched, err = dryrunApplyMatch(objBytes, foundBytes)
	if err != nil {
		return false, errors.Wrap(err, "error occured during dryrun apply match")
	}
	if matched {
		return true, nil
	}
	// CASE4: dryrun patch match
	matched, err = dryrunPatchMatch(objBytes, foundBytes)
	if err != nil {
		return false, errors.Wrap(err, "error occured during dryrun patch match")
	}
	if matched {
		return true, nil
	}
	return false, errors.New("specified object does not match with a YAML manifest in image")
}

func directMatch(objBytes, manifestBytes []byte) (bool, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize manifest node")
	}
	maskedObjNode := objNode.Mask(kubeutil.CommonMessageMask)
	maskedMnfNode := mnfNode.Mask(kubeutil.CommonMessageMask)
	diff := maskedObjNode.Diff(maskedMnfNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil
	}
	return false, nil
}

func dryrunCreateMatch(objBytes, manifestBytes []byte) (bool, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize manifest node")
	}
	nsMaskedManifestBytes := mnfNode.Mask([]string{"metadata.namespace"}).ToYaml()
	simBytes, err := kubeutil.DryRunCreate([]byte(nsMaskedManifestBytes), defaultDryRunNamespace)
	if err != nil {
		return false, errors.Wrap(err, "failed to dryrun with the found YAML in image")
	}
	simNode, err := mapnode.NewFromYamlBytes(simBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize dry-run-generated object node")
	}
	mask := kubeutil.CommonMessageMask
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil
	}
	return false, nil
}

func dryrunApplyMatch(objBytes, manifestBytes []byte) (bool, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize object node")
	}
	objNamespace := objNode.GetString("metadata.namespace")
	_, patchedBytes, err := kubeutil.GetApplyPatchBytes(manifestBytes, objNamespace)
	if err != nil {
		return false, errors.Wrap(err, "error during getting patched bytes")
	}
	patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
	nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
	simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), defaultDryRunNamespace)
	if err != nil {
		return false, errors.Wrap(err, "error during DryRunCreate for Patch")
	}
	simNode, _ := mapnode.NewFromYamlBytes(simPatchedObj)
	mask := kubeutil.CommonMessageMask
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil
	}
	return false, nil

}

func dryrunPatchMatch(objBytes, manifestBytes []byte) (bool, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize object node")
	}
	patchedBytes, err := kubeutil.StrategicMergePatch(objBytes, manifestBytes, "")
	if err != nil {
		return false, errors.Wrap(err, "error during getting patched bytes")
	}
	patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
	nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
	simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), defaultDryRunNamespace)
	if err != nil {
		return false, errors.Wrap(err, "error during DryRunCreate for Patch:")
	}
	simNode, _ := mapnode.NewFromYamlBytes(simPatchedObj)
	mask := kubeutil.CommonMessageMask
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil
	}
	return false, nil
}
