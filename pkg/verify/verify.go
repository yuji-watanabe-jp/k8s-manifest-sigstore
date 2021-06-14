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
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type VerifyResult struct {
	Verfied bool
	Signer  string
}

func Verify(manifest []byte, imageRef, keyPath string) (*VerifyResult, error) {
	if manifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}

	verified := false
	signerName := ""

	// TODO: support directly attached annotation sigantures
	if imageRef != "" {
		image, err := k8ssigutil.PullImage(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		ok, err := matchManifest(manifest, image)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		if !ok {
			return nil, errors.New("failed to match manifest with image")
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

func imageVerify(imageRef string, pubkeyPath *string) (bool, string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse image ref `%s`; %s", imageRef, err.Error())
	}

	co := &cosign.CheckOpts{
		Claims: true,
		Tlog:   true,
		Roots:  fulcio.Roots,
	}

	// TODO: support verify with pubkey

	// if pubkeyPath != nil {
	// 	tmpPubkey, err := LoadPubkey(*pubkeyPath)
	// 	if err != nil {
	// 		return false, "", fmt.Errorf("error loading public key; %s", err.Error())
	// 	}
	// 	co.PubKey = tmpPubkey
	// }

	rekorSever := cli.TlogServer()
	verified, err := cosign.Verify(context.Background(), ref, co, rekorSever)
	if err != nil {
		return false, "", fmt.Errorf("error occured while verifying image `%s`; %s", imageRef, err.Error())
	}
	if len(verified) == 0 {
		return false, "", fmt.Errorf("no verified signatures in the image `%s`; %s", imageRef, err.Error())
	}
	var cert *x509.Certificate
	for _, vp := range verified {
		ss := payload.SimpleContainerImage{}
		err := json.Unmarshal(vp.Payload, &ss)
		if err != nil {
			continue
		}
		cert = vp.Cert
		break
	}
	signerName := k8ssigutil.GetNameInfoFromCert(cert)
	return true, signerName, nil
}

func matchManifest(manifest []byte, image v1.Image) (bool, error) {
	manifestInImage, err := k8ssigutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return false, err
	}

	// now doing here
	return true, nil
}
