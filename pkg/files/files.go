package files

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
	ReadGroup string `json:"readGroup"`
	WriteGroup string `json:"writeGroup"`
}

type Entry struct {
	Name string
	Size string
	Mime string
	IsDir bool
}

type byType []Entry

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

func ReadFiles(where string) ([]Entry, *Entry) {
	prefix := HostDir
	if strings.HasPrefix(where, prefix) {
		prefix = ""
	}
	fullPath := path.Join(prefix, where)
	files, err := os.ReadDir(fullPath)
	if err != nil {
		info, err := os.Stat(fullPath)
		if err != nil {
			return []Entry{}, nil
		}
		return []Entry{}, &Entry{
			Name: info.Name(),
			IsDir: false,
			Mime: getMime(fullPath),
		}
	}
	entries := make([]Entry, 0, len(files) - 1)
	for _, f := range files {
		if f.Name() == MetaFile {
			continue;
		}
		entries = append(entries, Entry{
			Name: f.Name(),
			IsDir: f.IsDir(),
			Mime: "directory",
		})
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

func Mkdir(name, read, write string) (string, error) {
	err := os.Mkdir(name, 0755)
	if err != nil {
		return "", err
	}

	meta := &ChestMeta{
		ReadGroup: read,
		WriteGroup: write,
	}
	
	bytes, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	file := name + "/" + MetaFile
	err = os.WriteFile(file, bytes, 0644)
	if err != nil {
		return "", err
	}
	return name, nil
}
