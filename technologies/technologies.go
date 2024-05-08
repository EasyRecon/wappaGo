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
			requires := technoList[technoName].(map[string]interface{})["requires"]
			// Tentative d'assertion du type directement en string
			if reqString, ok := requires.(string); ok {
			    tech = AddTechno(reqString, tech, technoList)
			} else if reqMap, ok := requires.(map[string]interface{}); ok {
			    // Le contenu de requires est un map[string]interface{}, on itère sur les clés
			    for req := range reqMap {
			        tech = AddTechno(req, tech, technoList)
			    }
			} else if reqSlice, ok := requires.([]interface{}); ok {
			    // Le contenu de requires est un slice d'interface{}, on itère sur les éléments
			    for _, item := range reqSlice {
			        if itemStr, ok := item.(string); ok {
			            tech = AddTechno(itemStr, tech, technoList)
			        } else {
			            fmt.Println("Unsupported item type in 'requires' slice")
			        }
			    }
			} else {
			    // Si aucun des types attendus n'est rencontré, affiche une erreur
			    fmt.Println("Unexpected type for 'requires'")
			}
		}
		if name == "implies" {
			implies := technoList[technoName].(map[string]interface{})["implies"]
			switch v := implies.(type) {
			case string:
			    // Si c'est une chaîne, on ajoute directement la technologie
			    tech = AddTechno(v, tech, technoList)
			case []interface{}:
			    // Si c'est un slice, on itère sur chaque élément
			    for _, item := range v {
			        if strItem, ok := item.(string); ok {
			            tech = AddTechno(strItem, tech, technoList)
			        } else {
			            fmt.Println("Unexpected item type in 'implies' slice")
			        }
			    }
			case map[string]interface{}:
			    // Si c'est un map, on itère sur chaque clé
			    for key := range v {
			        tech = AddTechno(key, tech, technoList)
			    }
			default:
			    fmt.Println("Unexpected type for 'implies'")
			}
		}
	}
	return tech
}
func AddTechno(name string, tech []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	technoTemp := structure.Technologie{}
	technoTemp.Name = name
	if _, ok := technoList[name].(map[string]interface{})["cpe"]; ok {
		technoTemp.Cpe = technoList[name].(map[string]interface{})["cpe"].(string)
	}
	tech = append(tech, technoTemp)
	return tech
}

func DownloadTechnologies() (string, error) {
	files := []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
	folder := lib.RandStringBytes(20)
	_ = os.Mkdir(folder, 0766)
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
		for i, checkTech := range output {
			if checkTech == tech {
				add = false
			} else {
				if checkTech.Name == tech.Name {
					if tech.Version != "" && checkTech.Version == "" {
						output[i].Version = tech.Version
					}
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
