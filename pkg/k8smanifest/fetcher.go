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
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
)

type ImageManifestFetcher struct {
	UseCache bool
	CacheDir string
}

func (f *ImageManifestFetcher) FetchYAMLManifest(imageRef string) ([]byte, error) {
	var manifestInImage []byte
	manifestLoadedFromCache := false
	var err error
	if f.UseCache {
		ok := false
		manifestInImage, ok, err = k8ssigutil.GetYAMLManifestCache(f.CacheDir, imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get YAML manifest from cache")
		}
		if ok {
			manifestLoadedFromCache = true
		}
	}
	if !manifestLoadedFromCache {
		image, err := k8ssigutil.PullImage(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		manifestInImage, err = k8ssigutil.GenerateConcatYAMLsFromImage(image)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get YAML manifest in image")
		}
	}
	if f.UseCache && !manifestLoadedFromCache {
		err := k8ssigutil.SetYAMLManifestCache(f.CacheDir, imageRef, manifestInImage)
		if err != nil {
			return nil, errors.Wrap(err, "failed to save YAML manifest cache")
		}
	}
	return manifestInImage, nil
}
