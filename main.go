/*
Copyright © 2020 iiusky sky@03sec.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
)

var vulhubPath string
var id int64

func init() {
	flag.StringVar(&vulhubPath, "p", "./vulhub", "vulnhub repo local path")
}

type VulhubAppStruct struct {
	ID    int      `json:"id"`
	App   string   `json:"app"`
	Path  string   `json:"path"`
	Cve   string   `json:"cve"`
	Name  string   `json:"name"`
	Files []string `json:"files"`
}

type VulhubAppMetaStruct struct {
	Name string `json:"name"`
	App  string `json:"app"`
	Cve  string `json:"cve"`
	Path string `json:"path"`
}

func getFiles(appPath string) (files []string) {
	filepath.Walk(appPath, func(xpath string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, strings.ReplaceAll(xpath, appPath, ""))
		}
		return nil
	})
	return files
}

func getAllDir(vulhubPath string, deep bool, appName string) (dirs []string) {
	files, _ := ioutil.ReadDir(vulhubPath)

	for _, f := range files {
		if f.IsDir() && !strings.Contains(f.Name(), ".git") && appName != "base" {
			if deep {
				dirs = append(dirs, getAllDir(path.Join(vulhubPath, f.Name()), false, f.Name())...)
			} else {
				dirs = append(dirs, appName+"/"+f.Name())
			}
		}
	}

	return dirs
}

func getVulhubMetaData() (metaDB []VulhubAppMetaStruct) {
	metaData, err := resty.New().R().Get("https://raw.githubusercontent.com/vulhub/vulhub-org/master/src/environments.json")

	if err != nil {
		fmt.Printf("Get vulhub meta data error %v\n", err)
		os.Exit(-2)
	}

	err = json.Unmarshal(metaData.Body(), &metaDB)

	if err != nil {
		fmt.Printf("Unmarshal vulhub meta data error %v\n", err)
		os.Exit(-3)
	}

	return metaDB
}

func build(vulhubPath string) {
	var apps []VulhubAppStruct
	metas := getVulhubMetaData()

	allDirs := getAllDir(path.Join(vulhubPath), true, "")

	for _, dir := range allDirs {
		for _, meta := range metas {
			if strings.ToLower(dir) == strings.ToLower(meta.Path) {
				atomic.AddInt64(&id, 1)
				apps = append(apps, VulhubAppStruct{
					ID:    int(id),
					Cve:   meta.Cve,
					Name:  meta.Name,
					App:   strings.Split(dir, "/")[0],
					Path:  dir,
					Files: getFiles(path.Join(vulhubPath, dir)),
				})
			}
		}
	}

	b, _ := json.Marshal(apps)
	fmt.Println(string(b))
}

func main() {
	flag.Parse()

	_, err := os.Stat(path.Join(vulhubPath))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	build(path.Join(vulhubPath))
}
