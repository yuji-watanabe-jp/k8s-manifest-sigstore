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

package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	goyaml "gopkg.in/yaml.v2"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

func FindYAMLsInDir(dirPath string) ([][]byte, error) {

	foundYAMLs := [][]byte{}
	var err error
	err = filepath.Walk(dirPath, func(fpath string, info os.FileInfo, err error) error {
		if err == nil && (path.Ext(info.Name()) == ".yaml" || path.Ext(info.Name()) == ".yml") {
			yamlBytes, err := ioutil.ReadFile(fpath)
			if err == nil && isK8sResourceYAML(yamlBytes) {
				foundYAMLs = append(foundYAMLs, yamlBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return foundYAMLs, nil
}

func ConcatenateYAMLs(yamls [][]byte) []byte {
	concatYamls := ""
	for i, y := range yamls {
		concatYamls = fmt.Sprintf("%s%s", concatYamls, string(y))
		if i < len(yamls)-1 {
			concatYamls = fmt.Sprintf("%s\n---\n", concatYamls)
		}
	}
	return []byte(concatYamls)
}

func SplitConcatYAMLs(yaml []byte) [][]byte {
	yamls := [][]byte{}
	r := bytes.NewReader(yaml)
	dec := k8syaml.NewYAMLToJSONDecoder(r)
	var t interface{}
	for dec.Decode(&t) == nil {
		tB, err := goyaml.Marshal(t)
		if err != nil {
			continue
		}
		yamls = append(yamls, tB)
	}
	return yamls
}

func isK8sResourceYAML(data []byte) bool {
	var obj *unstructured.Unstructured
	err := yaml.Unmarshal(data, &obj)
	if err == nil {
		return true
	}
	return false
}
