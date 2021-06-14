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
	"strings"

	"github.com/spf13/cobra"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	k8sverify "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/verify"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdVerifyResource() *cobra.Command {

	var imageRef string
	var keyPath string
	var namespace string
	cmd := &cobra.Command{
		Use:   "verify-resource -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, kubeGetArgs := splitArgs(args)
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

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "image name in which you execute argocd-buidler-core")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "namespace of specified resource")

	return cmd
}

func verifyResource(kubeGetArgs []string, imageRef, keyPath, namespace string) error {
	kArgs := []string{"get", "--output", "json"}
	kArgs = append(kArgs, kubeGetArgs...)
	fmt.Println("[DEBUG] kube get args", strings.Join(kArgs, " "))
	resultJSON, err := k8ssigutil.CmdExec("kubectl", kArgs...)
	if err != nil {
		return err
	}
	var tmpObj unstructured.Unstructured
	err = json.Unmarshal([]byte(resultJSON), &tmpObj)
	if err != nil {
		return err
	}
	objs := []unstructured.Unstructured{}
	if tmpObj.IsList() {
		tmpList, _ := tmpObj.ToList()
		for _, tmp := range tmpList.Items {
			objs = append(objs, tmp)
		}
	} else {
		objs = append(objs, tmpObj)
	}

	result, err := k8sverify.VerifyResource(objs, imageRef, keyPath)
	if err != nil {
		return err
	}
	fmt.Println("[DEBUG] verify result:\n", result)
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
