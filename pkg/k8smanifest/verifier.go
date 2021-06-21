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
	"github.com/pkg/errors"
	k8scosign "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/cosign"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
)

type ImageSignatureVerifier struct {
	UseCache bool
	CacheDir string
}

func (v *ImageSignatureVerifier) Verify(imageRef string, keyPath *string) (bool, string, error) {
	verified := false
	signerName := ""
	var err error
	imageVerifyLoadedFromCache := false
	if v.UseCache {
		ok := false
		verified, signerName, ok, err = k8ssigutil.GetImageVerifyResultCache(v.CacheDir, imageRef, *keyPath)
		if err != nil {
			return false, "", errors.Wrap(err, "failed to get image verify result cache")
		}
		if ok {
			imageVerifyLoadedFromCache = true
		}
	}

	if !imageVerifyLoadedFromCache {
		verified, signerName, err = k8scosign.VerifyImage(imageRef, keyPath)
		if err != nil {
			return false, "", errors.Wrap(err, "error occurred during image verification")
		}
	}
	if v.UseCache && !imageVerifyLoadedFromCache {
		err := k8ssigutil.SetImageVerifyResultCache(v.CacheDir, imageRef, *keyPath, verified, signerName)
		if err != nil {
			return false, "", errors.Wrap(err, "failed to save image verify result cache")
		}
	}
	return verified, signerName, nil
}
