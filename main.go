package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"
)

type ruleFile struct {
	RuleFiles []string `yaml:"rules_files"`
}

type items struct {
	Date  string  `json:"date,omitempty"`
	Items []*item `json:"items,omitempty"`
}

type item struct {
	firstLine             int
	lastLine              int
	FileName              string                  `json:"file_name,omitempty"`
	Comment               string                  `json:"comment"`
	Permalink             string                  `json:"permalink,omitempty"`
	RequiredEngineVersion string                  `yaml:"required_engine_version" json:"required_engine_version,omitempty"`
	RequiredPluginVersion []requiredPluginVersion `yaml:"required_plugin_versions" json:"required_plugin_versions,omitempty" `
	Name                  string                  `json:"name,omitempty"`
	Rule                  string                  `yaml:"rule" json:"rule,omitempty"`
	Macro                 string                  `yaml:"macro" json:"macro,omitempty"`
	List                  string                  `yaml:"list" json:"list,omitempty"`
	Condition             string                  `yaml:"condition" json:"condition,omitempty"`
	Items                 []string                `yaml:"items" json:"items,omitempty"`
	Desc                  string                  `yaml:"desc" json:"desc,omitempty"`
	Output                string                  `yaml:"output" json:"output,omitempty"`
	Priority              string                  `yaml:"priority" json:"priority,omitempty"`
	Source                string                  `yaml:"source" json:"source,omitempty"`
	Tags                  []string                `yaml:"tags" json:"tags"`
	Enabled               string                  `yaml:"enabled" json:"enabled"`
	Dependencies          []string                `json:"dependencies,omitempty"`
	UsedBy                []string                `json:"used_by,omitempty"`
	RType                 string                  `json:"type,omitempty"`
	Hash                  string                  `json:"hash,omitempty"`
	Maturity              string                  `json:"maturity,omitempty"`
}

type requiredPluginVersion struct {
	Name    string `yaml:"name" json:"name,omitempty"`
	Version string `yaml:"version" json:"version,omitempty"`
}

var r items
var f ruleFile
var reg *regexp.Regexp

func init() {
	reg = regexp.MustCompile(`([a-zA-z_]+\.)+[a-z_]+`)
	registry, err := os.ReadFile("registry.yaml")
	checkErr(err)
	checkErr(yaml.Unmarshal(registry, &f))

	t := time.Now()
	fmt.Println(t.Unix())
	fmt.Println(t.Format("2006/02/01"))
	os.Exit(0)
}

func main() {
	downloadRuleFiles(f.RuleFiles)
	scrapeRuleFiles(f.RuleFiles)
	findDependencies(r)

	r.Date = time.Now().Format(time.RFC3339)

	log.Println("Generate index.json")
	j, err := json.Marshal(r)
	checkErr(err)
	checkErr(os.WriteFile("./index.json", j, 0644))
}

func downloadRuleFiles(f []string) {
	var wg sync.WaitGroup
	for _, i := range f {
		log.Printf("Download rules file: %v\n", i)
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			out, err := os.Create("./rules/" + getFileName(f))
			checkErr(err)
			defer out.Close()

			resp, err := http.Get(getRawURL(f))
			checkErr(err)

			defer resp.Body.Close()

			_, err = io.Copy(out, resp.Body)
			checkErr(err)
		}(i)
	}
	wg.Wait()
}

func getRawURL(s string) string {
	s = strings.ReplaceAll(s, "github.com", "raw.githubusercontent.com")
	s = strings.ReplaceAll(s, "blob/", "")
	return s
}

func setHashNameType(r items) {
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		switch {
		case i.Macro != "":
			i.Hash = fmt.Sprintf("%x", md5.Sum([]byte(i.Macro)))
			i.RType = "macro"
			i.Name = i.Macro
		case i.Rule != "":
			i.Hash = fmt.Sprintf("%x", md5.Sum([]byte(i.Rule)))
			i.RType = "rule"
			i.Name = i.Rule
		case i.List != "":
			i.Hash = fmt.Sprintf("%x", md5.Sum([]byte(i.List)))
			i.RType = "list"
			i.Name = i.List
		}
	}
}

func setLinePermaLinkFileName(r items, f string, n *[]yaml.Node) {
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		if i.RType == "rule" || i.RType == "macro" || i.RType == "list" {
			i.FileName = getFileName(f)
			i.firstLine, i.lastLine = findLines(i.RType, i.Name, n)
			i.Permalink = fmt.Sprintf("%v#L%v,L%v", f, i.firstLine, i.lastLine)
		}
	}
}

func setEnabled(r items) {
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		if i.Enabled == "" {
			i.Enabled = "true"
		}
	}
}

func setRequiredEngineVersion(r items) {
	var v string
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		if i.RequiredEngineVersion != "" {
			v = i.RequiredEngineVersion
		}
	}
	if v != "" {
		for _, i := range r.Items {
			if i == nil {
				continue
			}
			i.RequiredEngineVersion = v
		}
	}
}

func setRequiredPluginVersion(r items) {
	v := []requiredPluginVersion{}
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		if len(i.RequiredPluginVersion) != 0 {
			v = i.RequiredPluginVersion
		}
	}
	if len(v) != 0 {
		for _, i := range r.Items {
			if i == nil {
				continue
			}
			i.RequiredPluginVersion = v
		}
	}
}

func setComment(r items, n *[]yaml.Node) {
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		for _, j := range *n {
			if (i.firstLine == j.Line) && j.HeadComment != "" {
				s := strings.Split(j.HeadComment, "\n\n")
				i.Comment = s[len(s)-1]
			}
		}
	}
}

func setMaturity(r items, s string) {
	m := "unknown"
	if strings.Contains(s, "falco_rules") {
		m = "stable"
	}
	if strings.Contains(s, "deprecated") {
		m = "deprecated"
	}
	if strings.Contains(s, "incubating") {
		m = "incubating"
	}
	if strings.Contains(s, "sandbox") {
		m = "sandbox"
	}
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		i.Maturity = m
	}
}

func scrapeRuleFiles(f []string) {
	var wg sync.WaitGroup
	for _, i := range f {
		log.Printf("Scrape items from rules file: %v\n", i)
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			var v items
			var n []yaml.Node
			source, err := os.ReadFile("./rules/" + getFileName(f))
			checkErr(err)

			checkErr(yaml.Unmarshal(source, &v.Items))
			checkErr(yaml.Unmarshal(source, &n))
			setHashNameType(v)
			setEnabled(v)
			setRequiredEngineVersion(v)
			setRequiredPluginVersion(v)
			setLinePermaLinkFileName(v, f, &n)
			setComment(v, &n)
			setMaturity(v, f)
			for _, j := range v.Items {
				if j == nil {
					continue
				}
				if j.Macro == "" && j.List == "" && j.Rule == "" {
					continue
				}
				if j.Source == "" && j.RType == "rule" {
					j.Source = "syscalls"
				}
				r.Items = append(r.Items, j)
			}
		}(i)
	}
	wg.Wait()
}

func findDependencies(r items) {
	for _, i := range r.Items {
		if i == nil {
			continue
		}
		if i.Macro != "" {
			for _, j := range r.Items {
				if j == nil || i.Hash == j.Hash {
					continue
				}
				if j.List != "" {
					if strings.Contains(reg.ReplaceAllString(i.Condition, ""), j.List) {
						i.Dependencies = append(i.Dependencies, "list:"+j.Name+":"+j.Hash)
					}
				}
				if j.Macro != "" {
					if strings.Contains(reg.ReplaceAllString(i.Condition, ""), j.Macro) {
						i.Dependencies = append(i.Dependencies, "macro:"+j.Name+":"+j.Hash)
					}
					if strings.Contains(reg.ReplaceAllString(j.Condition, ""), i.Macro) {
						i.UsedBy = append(i.UsedBy, "macro:"+j.Name+":"+j.Hash)
					}
				}
				if j.Rule != "" {
					if strings.Contains(reg.ReplaceAllString(j.Condition, ""), i.Macro) {
						i.UsedBy = append(i.UsedBy, "rule:"+j.Name+":"+j.Hash)
					}
				}
			}
		}
		if i.Rule != "" {
			for _, j := range r.Items {
				if j == nil || i.Hash == j.Hash {
					continue
				}
				if j.List != "" {
					if strings.Contains(reg.ReplaceAllString(i.Condition, ""), j.List) {
						i.Dependencies = append(i.Dependencies, "list:"+j.Name+":"+j.Hash)
					}
				}
				if j.Macro != "" {
					if strings.Contains(reg.ReplaceAllString(i.Condition, ""), j.Macro) {
						i.Dependencies = append(i.Dependencies, "macro:"+j.Name+":"+j.Hash)
					}
				}
			}
		}
		if i.List != "" {
			for _, j := range r.Items {
				if j == nil || i.Hash == j.Hash {
					continue
				}
				if j.Macro != "" && i.Macro != j.Macro {
					if strings.Contains(reg.ReplaceAllString(j.Condition, ""), i.List) {
						i.UsedBy = append(i.UsedBy, "macro:"+j.Name+":"+j.Hash)
					}
				}
				if j.Rule != "" {
					if strings.Contains(reg.ReplaceAllString(j.Condition, ""), i.List) {
						i.UsedBy = append(i.UsedBy, "rule:"+j.Name+":"+j.Hash)
					}
				}
			}
		}
	}
}

func findLines(rtype, name string, nodes *[]yaml.Node) (int, int) {
	var firstLine, lastLine int
	for _, i := range *nodes {
		if len(i.Content) != 0 {
			if i.Content[0].Value == rtype && i.Content[1].Value == name {
				firstLine = i.Line
				lastLine = i.Content[len(i.Content)-1].Line
				return firstLine, lastLine
			}
		}
	}
	return 0, 0
}

func getFileName(s string) string {
	v := strings.Split(s, "/")
	return v[len(v)-1]
}

func checkErr(e error) {
	if e != nil {
		log.Fatalf(e.Error())
	}
}
