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

package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	k8ssigstoreutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	k8sverify "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/verify"
)

func NewCmdVerify() *cobra.Command {

	var imageRef string
	var inputDir string
	var keyPath string
	var output string
	cmd := &cobra.Command{
		Use:   "verify -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := sign(inputDir, imageRef, keyPath, output)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&inputDir, "filename", "f", "", "file name which will be signed (if dir, all YAMLs inside it will be signed)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "image name in which you execute argocd-buidler-core")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file name (if empty, use `<input>.signed`)")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")

	return cmd
}

func verify(inputDir, imageRef, keyPath, output string) error {
	if output == "" {
		output = inputDir + ".signed"
	}

	yamls, err := k8ssigstoreutil.FindYAMLsInDir(inputDir)
	if err != nil {
		return errors.Wrap(err, "failed to get YAMLs in a dir")
	}
	manifest := k8ssigstoreutil.ConcatenateYAMLs(yamls)

	result, err := k8sverify.Verify(manifest, imageRef, keyPath)
	if err != nil {
		return err
	}
	fmt.Println("[DEBUG] verify result:\n", result)
	return nil
}
