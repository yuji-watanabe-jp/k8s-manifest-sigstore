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

package cosign

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/pkg/errors"
	cosigncli "github.com/sigstore/cosign/cmd/cosign/cli"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
)

const certBeginByte = "-----BEGIN CERTIFICATE-----"
const certEndByte = "-----END CERTIFICATE-----"

func SignImage(imageRef string, keyPath *string) error {
	// TODO: check usecase for yaml signing
	imageAnnotation := map[string]interface{}{}

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	// TODO: handle the case that COSIGN_EXPERIMENTAL env var is not set

	opt := cosigncli.SignOpts{
		Annotations: imageAnnotation,
		Sk:          sk,
		IDToken:     idToken,
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
		opt.Pf = cosigncli.GetPass
	}

	return cosigncli.SignCmd(context.Background(), opt, imageRef, true, "", false, false)
}

func SignBlob(blobPath string, keyPath *string) (map[string][]byte, error) {
	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	opt := cosigncli.KeyOpts{
		Sk: sk,
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
	}

	m := map[string][]byte{}
	rawMsg, err := ioutil.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load a file to be signed")
	}
	base64Msg := []byte(base64.StdEncoding.EncodeToString(rawMsg))
	m["message"] = base64Msg

	returnValArray, stdoutAndErr := k8smnfutil.SilentExecFunc(cosigncli.SignBlobCmd, context.Background(), opt, blobPath, false, cosigncli.GetPass, idToken)

	fmt.Println(stdoutAndErr) // show cosign.SignBlobCmd() logs

	if len(returnValArray) != 2 {
		return nil, fmt.Errorf("cosign.SignBlobCmd() must return 2 values as output, but got %v values", len(returnValArray))
	}
	var rawSig []byte
	if returnValArray[0] != nil {
		rawSig = returnValArray[0].([]byte)
	}
	if returnValArray[1] != nil {
		err = returnValArray[1].(error)
	}
	if err != nil {
		return nil, errors.Wrap(err, "cosign.SignBlobCmd() returned an error")
	}

	base64Sig := []byte(base64.StdEncoding.EncodeToString(rawSig))
	m["signature"] = base64Sig

	rawCert := extractCertFromStdoutAndErr(stdoutAndErr)
	gzipCert := k8smnfutil.GzipCompress(rawCert)
	base64Cert := []byte(base64.StdEncoding.EncodeToString(gzipCert))
	m["certificate"] = base64Cert

	return m, nil
}

func extractCertFromStdoutAndErr(stdoutAndErr string) []byte {
	re := regexp.MustCompile(fmt.Sprintf(`(?s)%s.*%s`, certBeginByte, certEndByte)) // `(?s)` is necessary for matching multi lines
	foundBlocks := re.FindAllString(stdoutAndErr, 1)
	if len(foundBlocks) == 0 {
		return nil
	}
	return []byte(foundBlocks[0])
}
