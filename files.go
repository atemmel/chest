package main

import (
	"encoding/json"
	"mime"
	"os"
	"path"
	"sort"
	"strings"
)

const (
	MetaFile = ".chest_meta"
	HostDir = "files"
)

type ChestMeta struct {
	Group string `json:"group"`
}

type fileEntry struct {
	Name string
	Size string
	Mime string
	IsDir bool
}

type byType []fileEntry

func (s byType) Len() int {
	return len(s)
}

func (s byType) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byType) Less(i, j int) bool {
	lhs := &s[i]
	rhs := &s[j]

	if lhs.IsDir && !rhs.IsDir {
		return true;
	} else if !lhs.IsDir && rhs.IsDir {
		return false;
	}
	return lhs.Name < rhs.Name
}

func getMime(fullPath string) string {
	ext := path.Ext(fullPath)
	mime := mime.TypeByExtension(ext)
	if mime == "" {
		mime = "None/Unknown"
	}
	return mime
}

func readFiles(where string) ([]fileEntry, *fileEntry) {
	prefix := HostDir
	if strings.HasPrefix(where, prefix) {
		prefix = ""
	}
	fullPath := path.Join(prefix, where)
	files, err := os.ReadDir(fullPath)
	if err != nil {
		info, err := os.Stat(fullPath)
		if err != nil {
			return []fileEntry{}, nil
		}
		return []fileEntry{}, &fileEntry{
			Name: info.Name(),
			IsDir: false,
			Mime: getMime(fullPath),
		}
	}
	entries := make([]fileEntry, len(files))
	for i, f := range files {
		entries[i] = fileEntry{
			Name: f.Name(),
			IsDir: f.IsDir(),
			Mime: "directory",
		}
	}
	sort.Sort(byType(entries))
	return entries, nil
}

func ReadMeta(folder string) (*ChestMeta, error) {
	bytes, err := os.ReadFile(path.Join(folder, MetaFile))
	if err != nil {
		return nil, err
	}

	meta := &ChestMeta{}
	err = json.Unmarshal(bytes, meta)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

func Mkdir(name string, group string) (string, error) {
	if !strings.HasPrefix(name, "/" + HostDir) {
		name = path.Join(HostDir, name)
	} else {
		name = name[1:]
	}
	err := os.Mkdir(name, 0755)
	if err != nil {
		return "", err
	}

	meta := &ChestMeta{
		Group: group,
	}
	
	bytes, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(path.Join(name, MetaFile), bytes, 0644)
	if err != nil {
		return "", err
	}
	return name, os.Mkdir(name, 0755)
}
