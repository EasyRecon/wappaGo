package technologies

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/structure"

	"github.com/imdario/mergo"
)

func CheckRequired(technoName string, technoList map[string]interface{}, tech []structure.Technologie) []structure.Technologie {
	for name, _ := range technoList[technoName].(map[string]interface{}) {
		if name == "requires" {
			if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["requires"]) == "string" {
				technoTemp := structure.Technologie{}
				technoTemp.Name = technoList[technoName].(map[string]interface{})["requires"].(string)
				tech = append(tech, technoTemp)
			} else {
				if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["requires"].(map[string]interface{})) == "string" {
					technoTemp := structure.Technologie{}
					technoTemp.Name = technoList[technoName].(map[string]interface{})["requires"].(string)
					tech = append(tech, technoTemp)
				} else {
					for req, _ := range technoList[technoName].(map[string]interface{})["requires"].(map[string]interface{}) {
						technoTemp := structure.Technologie{}
						technoTemp.Name = req
						tech = append(tech, technoTemp)
					}
				}

			}
		}
		if name == "implies" {
			if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["implies"]) == "string" {
				technoTemp := structure.Technologie{}
				technoTemp.Name = technoList[technoName].(map[string]interface{})["implies"].(string)
				tech = append(tech, technoTemp)
			} else {
				if fmt.Sprintf("%T", technoList[technoName].(map[string]interface{})["implies"].(map[string]interface{})) == "string" {
					technoTemp := structure.Technologie{}
					technoTemp.Name = technoList[technoName].(map[string]interface{})["implies"].(string)
					tech = append(tech, technoTemp)
				} else {
					for req, _ := range technoList[technoName].(map[string]interface{})["implies"].(map[string]interface{}) {
						technoTemp := structure.Technologie{}
						technoTemp.Name = req
						tech = append(tech, technoTemp)
					}
				}

			}
		}
	}
	return tech
}

func DownloadTechnologies() (string, error) {
	files := []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	folder := lib.RandStringBytes(20)
	_ = os.Mkdir(folder, 0666)
	for _, f := range files {
		url := fmt.Sprintf("%v/technologies/%v.json", structure.WappazlyerRoot, f)
		resp, err := http.Get(url)
		if err != nil {
			return "", err
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		file, _ := os.OpenFile(
			folder+"/"+f+".json",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		file.Write(body)
		file.Close()

	}
	return folder, nil
}

func LoadTechnologiesFiles(folder string) map[string]interface{} {

	// Open our jsonFile
	var resultGlobal map[string]interface{}
	for _, s := range lib.Find(folder, ".json") {

		jsonFile, err := os.Open(s)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}

		json.Unmarshal([]byte(byteValue), &result)
		mergo.Merge(&resultGlobal, result)

	}
	return resultGlobal
}
func DedupTechno(technologies []structure.Technologie) []structure.Technologie {
	var output []structure.Technologie
	add := true
	for _, tech := range technologies {
		add = true
		for _, checkTech := range output {
			if checkTech == tech {
				add = false
			} else {
				if checkTech.Name == tech.Name && tech.Version == "" {
					add = false
				}
			}
		}
		if add {
			output = append(output, tech)
		}
	}
	return output
}
