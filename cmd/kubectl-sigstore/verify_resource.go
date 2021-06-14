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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdVerifyResource() *cobra.Command {

	var imageRef string
	var keyPath string
	var namespace string
	cmd := &cobra.Command{
		Use:   "verify-resource -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			fullArgs := getOriginalFullArgs("verify-resource")
			_, kubeGetArgs := splitArgs(fullArgs)
			if namespace != "" {
				kubeGetArgs = append(kubeGetArgs, []string{"--namespace", namespace}...)
			}

			err := verifyResource(kubeGetArgs, imageRef, keyPath, namespace)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "signed image name which bundles yaml files")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")

	return cmd
}

func verifyResource(kubeGetArgs []string, imageRef, keyPath, namespace string) error {
	kArgs := []string{"get", "--output", "json"}
	kArgs = append(kArgs, kubeGetArgs...)
	log.Debug("kube get args", strings.Join(kArgs, " "))
	resultJSON, err := k8ssigutil.CmdExec("kubectl", kArgs...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	var tmpObj unstructured.Unstructured
	err = json.Unmarshal([]byte(resultJSON), &tmpObj)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	objs := []unstructured.Unstructured{}
	if tmpObj.IsList() {
		tmpList, _ := tmpObj.ToList()
		objs = append(objs, tmpList.Items...)
	} else {
		objs = append(objs, tmpObj)
	}

	result, err := k8smanifest.VerifyResource(objs, imageRef, keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	if result.Verified {
		log.Info("verify result:", result)
	} else {
		log.Error("verify result:", result)
	}
	return nil
}

func splitArgs(args []string) ([]string, []string) {
	mainArgs := []string{}
	kubectlArgs := []string{}
	mainArgsCondition := map[string]bool{
		"--image": true,
		"-i":      true,
		"--key":   true,
		"-k":      true,
	}
	skipIndex := map[int]bool{}
	for i, s := range args {
		if skipIndex[i] {
			continue
		}
		if mainArgsCondition[s] {
			mainArgs = append(mainArgs, args[i])
			mainArgs = append(mainArgs, args[i+1])
			skipIndex[i+1] = true
		} else {
			kubectlArgs = append(kubectlArgs, args[i])
		}
	}
	return mainArgs, kubectlArgs
}
