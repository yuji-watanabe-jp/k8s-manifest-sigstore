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
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheDirName = "/tmp/.k8s-manifest-sigstore-image-cache/"
const cacheTTLSeconds = 10

type manifestCache struct {
	Data              []byte `json:"data"`
	CreationTimestamp int64  `json:"creationTimestamp"`
}

func cacheYAML(imageRef string, yamlBytes []byte) error {
	fpath := generateImageRefCachePath(imageRef)
	fdir := filepath.Dir(fpath)
	err := os.MkdirAll(fdir, 0777)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fpath, yamlBytes, 0777)
	if err != nil {
		return err
	}
	return nil
}

func GetYAMLInImageWithCache(imageRef string) ([]byte, error) {
	cachePath := generateImageRefCachePath(imageRef)
	if exists(cachePath) {
		var err error
		var cacheBytes []byte
		gzCacheBytes, err := ioutil.ReadFile(cachePath)
		cacheBytes = gzipDecompress(gzCacheBytes)
		if err == nil {
			var c *manifestCache
			err = json.Unmarshal(cacheBytes, &c)
			if err == nil {
				pullTime := time.Unix(c.CreationTimestamp, 0)
				if time.Now().UTC().Sub(pullTime).Seconds() < cacheTTLSeconds {
					return c.Data, nil
				}
			}
		}
		if err != nil {
			fmt.Println("[DEBUG] err; ", err)
		}
	}
	img, err := PullImage(imageRef)
	if err != nil {
		return nil, err
	}
	pullTimestamp := time.Now().UTC().Unix()
	concatYaml, err := GenerateConcatYAMLsFromImage(img)
	if err != nil {
		return nil, err
	}
	c := &manifestCache{
		Data:              concatYaml,
		CreationTimestamp: pullTimestamp,
	}
	cB, _ := json.Marshal(c)
	gCB := gzipCompress(cB)
	err = cacheYAML(imageRef, gCB)
	if err != nil {
		return nil, err
	}
	return concatYaml, nil
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateImageRefCachePath(imageRef string) string {
	imageRefString := normalizeImageRef(imageRef)
	return filepath.Join(cacheDirName, imageRefString)
}

func normalizeImageRef(imageRef string) string {
	imageRef = strings.ToLower(strings.TrimSpace(imageRef))
	imageRef = strings.ReplaceAll(imageRef, ":", "_")
	imageRef = strings.ReplaceAll(imageRef, "/", "_")

	imageRefURL, err := url.Parse(imageRef)
	if err != nil {
		return ""
	}
	return imageRefURL.String()
}

func gzipCompress(in []byte) []byte {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	writer.Write(in)
	writer.Close()
	return buffer.Bytes()
}

func gzipDecompress(in []byte) []byte {
	reader := bytes.NewReader(in)
	gzreader, _ := gzip.NewReader(reader)
	out, err := ioutil.ReadAll(gzreader)
	if err != nil {
		return in
	}
	return out
}
