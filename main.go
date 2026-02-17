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

type mergedYamlFile struct {
	Lists  []mergedItem `yaml:"lists"`
	Macros []mergedItem `yaml:"macros"`
	Rules  []mergedItem `yaml:"rules"`
}

type mergedItem struct {
	Info itemInfo `yaml:"info"`
}

type itemInfo struct {
	Name      string   `yaml:"name"`
	Items     []string `yaml:"items,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Desc      string   `yaml:"desc,omitempty"`
	Output    string   `yaml:"output,omitempty"`
	Priority  string   `yaml:"priority,omitempty"`
	Source    string   `yaml:"source,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`
	Enabled   string   `yaml:"enabled,omitempty"`
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
		// Skip local files (anything that's not a URL)
		if !strings.HasPrefix(i, "http://") && !strings.HasPrefix(i, "https://") {
			log.Printf("Skip local file: %v\n", i)
			continue
		}

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
	var m string
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

func isMergedFormat(source []byte) bool {
	// Try to parse as merged format and check for the presence of info sections
	var mf mergedYamlFile
	if err := yaml.Unmarshal(source, &mf); err != nil {
		return false
	}

	// Check if any lists/macros/rules have the merged format (info section)
	for _, list := range mf.Lists {
		if list.Info.Name != "" {
			return true
		}
	}
	for _, macro := range mf.Macros {
		if macro.Info.Name != "" {
			return true
		}
	}
	for _, rule := range mf.Rules {
		if rule.Info.Name != "" {
			return true
		}
	}

	return false
}

func parseMergedFile(source []byte, v *items, fileName string) {
	var mf mergedYamlFile
	checkErr(yaml.Unmarshal(source, &mf))

	// Convert merged lists to items
	for _, list := range mf.Lists {
		item := &item{
			Name:     list.Info.Name,
			List:     list.Info.Name,
			Items:    list.Info.Items,
			Tags:     list.Info.Tags,
			RType:    "list",
			Enabled:  "true",
			FileName: getFileName(fileName),
		}
		if item.Enabled == "" {
			item.Enabled = "true"
		}
		item.Hash = fmt.Sprintf("%x", md5.Sum([]byte(item.List)))
		setMaturityFromTags(item)
		v.Items = append(v.Items, item)
	}

	// Convert merged macros to items
	for _, macro := range mf.Macros {
		item := &item{
			Name:      macro.Info.Name,
			Macro:     macro.Info.Name,
			Condition: macro.Info.Condition,
			Tags:      macro.Info.Tags,
			RType:     "macro",
			Enabled:   "true",
			FileName:  getFileName(fileName),
		}
		if item.Enabled == "" {
			item.Enabled = "true"
		}
		item.Hash = fmt.Sprintf("%x", md5.Sum([]byte(item.Macro)))
		setMaturityFromTags(item)
		v.Items = append(v.Items, item)
	}

	// Convert merged rules to items
	for _, rule := range mf.Rules {
		item := &item{
			Name:      rule.Info.Name,
			Rule:      rule.Info.Name,
			Condition: rule.Info.Condition,
			Desc:      rule.Info.Desc,
			Output:    rule.Info.Output,
			Priority:  rule.Info.Priority,
			Source:    rule.Info.Source,
			Tags:      rule.Info.Tags,
			Enabled:   rule.Info.Enabled,
			RType:     "rule",
			FileName:  getFileName(fileName),
		}
		if item.Enabled == "" {
			item.Enabled = "true"
		}
		if item.Source == "" {
			item.Source = "syscall"
		}
		item.Hash = fmt.Sprintf("%x", md5.Sum([]byte(item.Rule)))
		setMaturityFromTags(item)
		v.Items = append(v.Items, item)
	}

	// Apply filename-based maturity for items that don't have tag-based maturity
	setMaturity(*v, fileName)
}

func setMaturityFromTags(item *item) {
	for _, tag := range item.Tags {
		if strings.HasPrefix(tag, "maturity_") {
			item.Maturity = strings.TrimPrefix(tag, "maturity_")
			return
		}
	}
	// Leave maturity empty if no tag found (consistent with setMaturity behavior)
}

func scrapeRuleFiles(f []string) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, i := range f {
		log.Printf("Scrape items from rules file: %v\n", i)
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			var v items
			var n []yaml.Node
			var filePath string
			if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
				// URL file downloaded to ./rules/
				filePath = "./rules/" + getFileName(f)
			} else {
				// Local file - use path as-is
				filePath = f
			}
			source, err := os.ReadFile(filePath)
			checkErr(err)

			// Try to detect file format by content structure
			if isMergedFormat(source) {
				parseMergedFile(source, &v, f)
			} else {
				checkErr(yaml.Unmarshal(source, &v.Items))
				checkErr(yaml.Unmarshal(source, &n))
				setHashNameType(v)
				setEnabled(v)
				setRequiredEngineVersion(v)
				setRequiredPluginVersion(v)
				setLinePermaLinkFileName(v, f, &n)
				setComment(v, &n)
				setMaturity(v, f)
			}

			mu.Lock()
			for _, j := range v.Items {
				if j == nil {
					continue
				}
				if j.Macro == "" && j.List == "" && j.Rule == "" {
					continue
				}
				if j.Source == "" && j.RType == "rule" {
					j.Source = "syscall"
				}
				r.Items = append(r.Items, j)
			}
			mu.Unlock()
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
				if i.Maturity != j.Maturity {
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
				if i.Maturity != j.Maturity {
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
				if i.Maturity != j.Maturity {
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
