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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
)

const (
	tmpMessageFile     = "k8s-manifest-sigstore-message"
	tmpCertificateFile = "k8s-manifest-sigstore-certificate"
	tmpSignatureFile   = "k8s-manifest-sigstore-signature"
)

func VerifyImage(imageRef string, pubkeyPath *string) (bool, string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse image ref `%s`; %s", imageRef, err.Error())
	}

	co := &cosign.CheckOpts{
		Claims: true,
		Tlog:   true,
		Roots:  fulcio.Roots,
	}

	if pubkeyPath != nil && *pubkeyPath != "" {
		tmpPubkey, err := cosign.LoadPublicKey(context.Background(), *pubkeyPath)
		if err != nil {
			return false, "", fmt.Errorf("error loading public key; %s", err.Error())
		}
		co.PubKey = tmpPubkey
	}

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
	signerName := "" // singerName could be empty in case of key-used verification
	if cert != nil {
		signerName = k8smnfutil.GetNameInfoFromCert(cert)
	}
	return true, signerName, nil
}

func VerifyBlob(msgBytes, sigBytes, certBytes []byte, pubkeyPath *string) (bool, string, error) {
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(dir)

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false

	opt := cli.KeyOpts{
		Sk: sk,
	}

	if pubkeyPath != nil {
		opt.KeyRef = *pubkeyPath
	}

	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawSig, _ := base64.StdEncoding.DecodeString(string(sigBytes))
	gzipCert, _ := base64.StdEncoding.DecodeString(string(certBytes))
	rawCert := k8smnfutil.GzipDecompress(gzipCert)
	msgFile := filepath.Join(dir, tmpMessageFile)
	sigFile := filepath.Join(dir, tmpSignatureFile)
	certFile := filepath.Join(dir, tmpCertificateFile)
	_ = ioutil.WriteFile(msgFile, gzipMsg, 0777) // signed blob is .tar.gz, so create gzip bytes
	_ = ioutil.WriteFile(sigFile, rawSig, 0777)
	_ = ioutil.WriteFile(certFile, rawCert, 0777)

	returnValArray, stdoutAndErr := k8smnfutil.SilentExecFunc(cli.VerifyBlobCmd, context.Background(), opt, certFile, sigFile, msgFile)
	if len(returnValArray) != 1 {
		return false, "", fmt.Errorf("cosign.VerifyBlobCmd() must return 1 values as output, but got %v values", len(returnValArray))
	}
	if returnValArray[0] != nil {
		err = returnValArray[0].(error)
	}
	if err != nil {
		err = fmt.Errorf("error: %s, detail logs during cosign.VerifyBlobCmd(): %s", err.Error(), stdoutAndErr)
		return false, "", errors.Wrap(err, "cosign.VerifyBlobCmd() returned an error")
	}
	verified := false
	if err == nil {
		verified = true
	}

	cert, err := loadCertificate(rawCert)
	if err != nil {
		return false, "", errors.Wrap(err, "failed to load certificate")
	}
	signerName := getNameInfoFromCert(cert)

	return verified, signerName, nil
}

func loadCertificate(pemBytes []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(pemBytes)
	if p == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return x509.ParseCertificate(p.Bytes)
}

func getNameInfoFromCert(cert *x509.Certificate) string {
	name := ""
	if len(cert.EmailAddresses) > 0 {
		name = cert.EmailAddresses[0]
	}
	return name
}
