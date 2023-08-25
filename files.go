package main

import (
	"fmt"
	"mime"
	"os"
	"path"
	"sort"
	"strings"
)

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
	prefix := "files"
	if strings.HasPrefix(where, prefix) {
		prefix = ""
	}
	fullPath := path.Join(prefix, where)
	files, err := os.ReadDir(fullPath)
	if err != nil {
		info, err := os.Stat(fullPath)
		if err != nil {
			fmt.Println("a", err)
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
			fmt.Println("c")
	return entries, nil
}
