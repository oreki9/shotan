package main

import (
	"fmt"
	"encoding/base64"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
    "log"
	"strconv"
	"net/http"
	"encoding/json"
	// "os"
	// "bufio"
	// "strings"
	e "github.com/oreki9/shotan/Entity"
	p "github.com/oreki9/shotan/Utils"
	// "github.com/oreki9/lexer"// update to lexer oreki9 because some is custom code
)



func main() {
	http.HandleFunc("/", handler) // Route "/"
    
    fmt.Println("Server running on http://localhost:8080")
    http.ListenAndServe(":8080", nil) // Start server on port 8080
}
func mainParse(){
	
}
func createGetAllTable(valueSelect string, idx int) []e.Command {
	var generateAllTableSelect = []string{
		"info.title='%s'",
		"OR info.value='%s'",
		"OR vuln.title='%s'",
		"OR vuln.value='%s'",
		"OR tag.title='%s'",
		"OR port.title='%s'",
		"OR port.value='%s'",
		"OR tech.title='%s'",
		"OR tech.value='%s'",
	}
	var patternIndex = []int{
		33, 17, 17, 17, 17, 17, 17, 17, 17, 17,
	}
	allParsedCommand := []e.Command{}
	for idxCheck, val := range generateAllTableSelect {
		// fmt.Println(valueSelect)
		allParsedCommand = append(allParsedCommand, e.Command{
			CommandPatern: p.ParseCommand(fmt.Sprintf(val, valueSelect)),
			IndexPatern: patternIndex[idxCheck],
		})
	}
	return allParsedCommand
}

//list table:
//generalinfo
//port
//vuln
//tag

//after name table is column or value of title:
//generalinfo.isp (is title) generalinfo
//generalinfo.title (is column title), table that have title/desc = port, vuln

func getSQLResultid(db *sql.DB, query string, value []string) (bool, int64, sql.Result, error) {
	result, err := db.Exec(query, interfaceSlice(value)...)
	var isError bool = false
	if err != nil {
		isError = true
	}
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		isError = true
	}
	return isError, lastInsertID, result, err
}
func interfaceSlice(slice []string) []interface{} {
	args := make([]interface{}, len(slice))
	for i, v := range slice {
		args[i] = v
	}
	return args
}

func handler(w http.ResponseWriter, r *http.Request) {
    // fmt.Println(r.URL.Path)
	db, err := sql.Open("mysql", "root:1919@(127.0.0.1:3306)/shotan")
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}
	enableCORS(w)
	if(r.URL.Path == "/detail"){
		ipAddress := r.URL.Query().Get("ip") // Extract "name" parameter from URL
		detailIp := p.GetDetailIpAddress(db, ipAddress, []int{})
		jsonData, err := json.Marshal(detailIp) // Convert struct to JSON
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Fprintf(w, string(jsonData))
	}else if(r.URL.Path == "/search"){
		// parseCommand("info.country=japan vuln.title=2020")
		// parseCommand("info.country=japan vuln=2020")
		// parsedStr := parseCommand("info=japan and vuln=klepon")
		// parsedStr := parseCommand("cosco")	
		// parsedStr := parseCommand("info.country=japan or vuln.title='doby'")
		// parsedStr := parseCommand("info.country=japan and vuln.title='doby'")
		commandStr := r.URL.Query().Get("cmd")
		pageStr := strconv.Itoa((parseInt(r.URL.Query().Get("page"))-1))
		commandRet, err := base64.StdEncoding.DecodeString(commandStr)
		if err != nil {
			log.Fatal("Error decoding Base64:", err)
		}
		fmt.Println(string(commandRet))
		parsedStr := p.ParseCommand(string(commandRet))
		listCommand := []e.Command{}
		lastTokenPos := []e.TokenPos{}
		invalidToken := []e.TokenPos{}
		for _, token := range parsedStr {//check patern command query
			isInPatern, indexPatern, isComplete := p.CheckPaternToken(append(lastTokenPos, token))
			if(isComplete){
				if (indexPatern>p.GetIndexPaternWithAllTable){
					listCommand = append(listCommand, createGetAllTable(token.Lit, indexPatern)...)
					// fmt.Println(listCommand)
				}else{
					lastTokenPos = append(lastTokenPos, token)
					listCommand = append(listCommand, e.Command{
						CommandPatern: lastTokenPos,
						IndexPatern: indexPatern,
					})
					lastTokenPos = nil
				}
			}else if isInPatern {
				lastTokenPos = append(lastTokenPos, token)
			}else if isInPatern == false {
				// fmt.Println("whoa")
				// fmt.Println(indexPatern)
				for _, val := range append(lastTokenPos, token) {
					fmt.Print(p.GetTokenValue(val))
				}
				fmt.Println("")
				if(len(token.Lit)>0){
					invalidToken = append(invalidToken, token)
				}
				lastTokenPos = nil
			}
		}
		var selectSameTable = [][]string{}
		for tableName, value := range p.CreateCommandSameTable(listCommand) {
			_, opValue := p.StartOperatorSameTable(value)
			selectSameTable = append(selectSameTable, []string{
				tableName,
				opValue,
				p.CreateBaseSqlToSelect(value),
			})
		}
		getRelSql := func(s string) string {
			switch(s){
			case "OR": return "UNION"
			case "AND": return "INTERSECT"
			default: return ""	
			}
		}
		collectionTable := ""
		collectionCountTable := ""
		// countcollectTable := "" 
		for idx, Arrvalue := range selectSameTable {
			if(idx == 0){
				collectionCountTable+=fmt.Sprintf("(SELECT %s FROM %s)", "l.`ipaddress`", Arrvalue[2])
				collectionTable+=fmt.Sprintf("(SELECT %s FROM %s limit 10 OFFSET %s)", "l.`ipaddress`", Arrvalue[2], pageStr)
			}else{
				collectionCountTable+=fmt.Sprintf(" %s (SELECT %s FROM %s)", getRelSql(Arrvalue[1]), "l.`ipaddress`", Arrvalue[2])
				collectionTable+=fmt.Sprintf(" %s (SELECT %s FROM %s limit 10 OFFSET %s)", getRelSql(Arrvalue[1]), "l.`ipaddress`", Arrvalue[2], pageStr)
			}
		}
		countAllSQL := fmt.Sprintf("SELECT %s FROM (%s) AS ResultTable", "COUNT(*)", collectionCountTable)
		isCountError, CountAllRes, _ := p.GetSQLData(db, countAllSQL)
		countAllIp := 0
		if(!isCountError){
			defer CountAllRes.Close()
			CountAllRes.Next()
			err := CountAllRes.Scan(&countAllIp)
			if err != nil { log.Fatal(err) }
		}
		selectAllSQL := fmt.Sprintf("SELECT %s FROM (%s) AS ResultTable", "*", collectionTable)
		fmt.Println(selectAllSQL)
		isSelectError, SelectRes, _ := p.GetSQLData(db, selectAllSQL)
		listIpAddress := []e.IPAddressGenInfo{}
		if(!isSelectError){
			defer SelectRes.Close()
			for SelectRes.Next() {
				var ipString = ""
				err := SelectRes.Scan(&ipString)
				if err != nil { log.Fatal(err) }
				detailIp := p.GetDetailIpAddress(db, ipString, []int{1,2,3,4})
				// fmt.Println(detailIp)
				listIpAddress = append(listIpAddress, e.IPAddressGenInfo{
					Ipaddress: ipString,
					Geninfo: detailIp.Geninfo, 
				})
			}
		}
		returnObj := e.ListIpAddressObj {
			MaxPage: strconv.Itoa(countAllIp),
			Index: pageStr,
			List: listIpAddress,
		}
		jsonData, err := json.Marshal(returnObj) // Convert struct to JSON
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Fprintf(w, string(jsonData))
	}else{
		fmt.Fprintf(w, "No Response")
	}
}
func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // Allow all origins
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
func parseInt(val string) int {
	num, err := strconv.Atoi(val)
    if err != nil {
        return 0
    }
	return num
}
