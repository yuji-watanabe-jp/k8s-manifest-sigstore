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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheTTLSeconds = 10

type manifestCache struct {
	Data              []byte `json:"data"`
	CreationTimestamp int64  `json:"creationTimestamp"`
}

type imageVerifyCache struct {
	Verified          bool   `json:"verified"`
	SignerName        string `json:"signerName"`
	CreationTimestamp int64  `json:"creationTimestamp"`
}

func cacheData(fpath string, data []byte) error {
	fdir := filepath.Dir(fpath)
	err := os.MkdirAll(fdir, 0777)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fpath, data, 0777)
	if err != nil {
		return err
	}
	return nil
}

func SetYAMLManifestCache(cacheDir, imageRef string, yamlBytes []byte) error {
	c := &manifestCache{
		Data:              yamlBytes,
		CreationTimestamp: time.Now().UTC().Unix(),
	}
	cB, _ := json.Marshal(c)
	gCB := gzipCompress(cB)
	fpath := generateYAMLCachePath(cacheDir, imageRef)
	err := cacheData(fpath, gCB)
	if err != nil {
		return err
	}
	return nil
}

func GetYAMLManifestCache(cacheDir, imageRef string) ([]byte, bool, error) {
	cachePath := generateYAMLCachePath(cacheDir, imageRef)
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
					return c.Data, true, nil
				}
			}
		}
		if err != nil {
			fmt.Println("[DEBUG] err; ", err)
		}
	}

	return nil, false, nil
}

func SetImageVerifyResultCache(cacheDir, imageRef, keyPath string, verified bool, signerName string) error {
	c := &imageVerifyCache{
		Verified:          verified,
		SignerName:        signerName,
		CreationTimestamp: time.Now().UTC().Unix(),
	}
	cB, _ := json.Marshal(c)
	gCB := gzipCompress(cB)
	fpath := generateImageVerifyCachePath(cacheDir, imageRef, keyPath)
	err := cacheData(fpath, gCB)
	if err != nil {
		return err
	}
	return nil
}

func GetImageVerifyResultCache(cacheDir, imageRef, keyPath string) (bool, string, bool, error) {
	cachePath := generateImageVerifyCachePath(cacheDir, imageRef, keyPath)
	if exists(cachePath) {
		var err error
		var cacheBytes []byte
		gzCacheBytes, err := ioutil.ReadFile(cachePath)
		cacheBytes = gzipDecompress(gzCacheBytes)
		if err == nil {
			var c *imageVerifyCache
			err = json.Unmarshal(cacheBytes, &c)
			if err == nil {
				pullTime := time.Unix(c.CreationTimestamp, 0)
				if time.Now().UTC().Sub(pullTime).Seconds() < cacheTTLSeconds {
					return c.Verified, c.SignerName, true, nil
				}
			}
		}
		if err != nil {
			fmt.Println("[DEBUG] err; ", err)
		}
	}

	return false, "", false, nil
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateYAMLCachePath(cacheDir, imageRef string) string {
	imageRefString := normalizeImageRef(imageRef)
	return filepath.Join(cacheDir, "yaml", imageRefString)
}

func generateImageVerifyCachePath(cacheDir, imageRef, keyPath string) string {
	imageRefString := normalizeImageRef(imageRef)
	keyPathHash := md5.Sum([]byte(keyPath))
	keyPathHashStr := fmt.Sprintf("%x", keyPathHash)
	return filepath.Join(cacheDir, "verify", imageRefString, keyPathHashStr)
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
