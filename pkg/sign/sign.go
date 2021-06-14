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

package sign

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"

	cosigncli "github.com/sigstore/cosign/cmd/cosign/cli"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

type SigningMode string

const (
	SigningModeUnknown          SigningMode = ""
	SigningModeAnnotationDirect SigningMode = "annotation"
	SigningModeAnnotationImage  SigningMode = "annotation-image"
	SigningModeRegistryImage    SigningMode = "image"
)

func Sign(manifest []byte, imageRef, keyPath, output string) (string, error) {
	if manifest == nil {
		return "", errors.New("input YAML manifest must be non-empty")
	}

	if imageRef != "" {
		err := uploadFileToRegistry(manifest, imageRef)
		if err != nil {
			return "", errors.New("failed to upload image with manifest")
		}
		err = signImage(imageRef, keyPath)
	}

	// TODO: generate a signed manifest file

	return "", nil
}

func uploadFileToRegistry(manifest []byte, imageRef string) error {
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fpath := filepath.Join(dir, "manifest.yaml")
	err = ioutil.WriteFile(fpath, manifest, 0644)
	if err != nil {
		return err
	}

	files := []cremote.File{
		{Path: fpath},
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	_, err = cremote.UploadFiles(ref, files)
	if err != nil {
		return err
	}
	return nil
}

func signImage(imageRef, keyPath string) error {
	// TODO: check usecase for yaml signing
	imageAnnotation := map[string]interface{}{}

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	// TODO: handle the case that COSIGN_EXPERIMENTAL env var is not set

	opt := cosigncli.SignOpts{
		KeyRef:      keyPath,
		Annotations: imageAnnotation,
		Sk:          sk,
		IDToken:     idToken,
	}

	return cosigncli.SignCmd(context.Background(), opt, imageRef, true, "", false, false)
}
