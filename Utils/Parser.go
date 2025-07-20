package Utils
import (
	"fmt"
	"strings"
	"github.com/oreki9/lexer"
	e "github.com/oreki9/shotan/Entity"
)

func ParseCommand(s string) []e.TokenPos {
    listToken := []e.TokenPos{}
	l := lexer.NewScannerString(s)
	for {
		tok, pos, lit := l.Scan()
		if tok == lexer.EOF { break }
		if tok == lexer.WS { continue }
		listToken = append(listToken, e.TokenPos{
			Tok: tok,
			Pos: pos,
			Lit: lit,
		})
	}
	return listToken
}
// maybe still have problem about illegal ``
func init() {
	// Loads keyword tokens into lexer
	lexer.LoadTokenMap(tokenMap)
}

// type ListIpAddressObj struct {
// 	List []string `json:"list"`
// }
const (
	// Starts the keywords with an offset from the built in tokens
	startKeywords lexer.Token = iota + 1000

	INFO
	
	VULN

	TAG

	PORT

	TECH

	TITLE

	VALUE
	
	endKeywords
)

var tokenMap = map[lexer.Token]string{
	INFO:   "INFO",
	VULN:   "VULN",
	TAG:   "TAG",
	PORT:   "PORT",
	TECH:   "TECH",

	TITLE:   "TITLE",
	VALUE:   "VALUE",
}

// IsKeyword returns true if the token is a custom keyword.
func IsKeyword(tok lexer.Token) bool {
	return tok > startKeywords && tok < endKeywords
}
func getIsCustomKeyword(s string) string {
	switch(s){
	case "INFO": fallthrough
	case "VULN": fallthrough
	case "TAG": fallthrough
	case "TECH": fallthrough
	case "PORT": return "CUSTOM"
	
	case "TITLE": fallthrough
	case "VALUE": return "CUSTOM"
	default: return s
	}
}
func operatorToSqlCommand(str string) string {
	switch(str){
	case "=": return " LIKE "
	default: return str
	}
}
func createKeyTokenIndex(token string, idx int) string {
	return fmt.Sprintf("%d", idx)
}
func GetTokenValue(tok e.TokenPos) string {
	if(len(tok.Lit)>0){
		return tok.Lit
	}else{
		return operatorToSqlCommand(fmt.Sprintf("%s", tok.Tok))
	}
}
func getTableNameFromPaternIndex(cmd e.Command) string {
	getIndex := func(idx int) int {
		if(idx>=0 && idx<=31){
			return 1
		}else if(idx>31 && idx<=42){
			return 0
		}else{ return -1 }
	}
	if(getIndex(cmd.IndexPatern) < 0) { return "" }
	return GetTokenValue(cmd.CommandPatern[getIndex(cmd.IndexPatern)])
}
func getColumnNameFromPaternIndex(cmd e.Command) string {
	getIndex := func(idx int) int {
		if(idx>=0 && idx<=7){
			return 3
		}else if(idx>7 && idx<=15){
			return -1
		}else if(idx>15 && idx<=23){
			return 3
		}else if(idx>23 && idx<=31){
			return 3
		}else if(idx>31 && idx<=38){
			return 2
		}else if(idx>39 && idx<=42){
			return -1
		}else{ return -1 }
	}
	if(getIndex(cmd.IndexPatern) < 0) { return "" }
	return GetTokenValue(cmd.CommandPatern[getIndex(cmd.IndexPatern)])
}
func getValueFromPaternIndex(cmd e.Command) string {
	getIndex := func(idx int) int {
		if(idx>=0 && idx<=7){
			return 5
		}else if(idx>7 && idx<=15){
			return 3
		}else if(idx>15 && idx<=23){
			return 5
		}else if(idx>23 && idx<=31){
			return 3
		}else if(idx>31 && idx<=38){
			return 4
		}else if(idx>39 && idx<=42){
			return 2
		}else{ return -1 }
	}
	if(getIndex(cmd.IndexPatern) < 0) { return "" }
	return GetTokenValue(cmd.CommandPatern[getIndex(cmd.IndexPatern)])
}
func CreateCommandSameTable(cmd []e.Command) map[string]e.CommandSameTable {
	var filterSameTable map[string]e.CommandSameTable
	filterSameTable = make(map[string]e.CommandSameTable)
	for _,item := range cmd {
		tableName := strToTable(getTableNameFromPaternIndex(item))
		valueCheck, isExist := filterSameTable[tableName]
		if(isExist) {
			valueCheck.Command = append(valueCheck.Command, item)
			filterSameTable[tableName] = valueCheck
		}else{
			filterSameTable[tableName] = e.CommandSameTable{
				Table: tableName,
				Command: []e.Command{item},
			}
		}
	}
	return filterSameTable
}
// result ex: columna = 'a' and columnb = 'b'
func createSameTableSql(cmd e.CommandSameTable) string {
	result := ""//ex: "table1.column like `%value%` AND table2.column like `%value%` "
	for idx, cmdItem := range cmd.Command {
		// var sqlCommandStr = ""//ex: and table1.column like `%value%`
		tableName := strToTable(getTableNameFromPaternIndex(cmdItem))
		columnName := getColumnNameFromPaternIndex(cmdItem)
		valueSql := getValueFromPaternIndex(cmdItem)
		isFirstItem := (idx==0)
		commandSameTableConcat := createSqlCheckCommand(isFirstItem, tableName, cmdItem.IndexPatern, columnName, valueSql)
		if((idx > 0)){
			if(!(commandSameTableConcat[0:3] == "AND" || commandSameTableConcat[0:2] == "OR")){
				result+="AND "
			}
		}
		result+=commandSameTableConcat
	}
	return result
	// fmt.Sprintf("%s",result)
}
func strToTable(s string) string {
	switch s{
		case "INFO": return "generalinfo"
		case "VULN": return "vulndesc"
		case "TAG": return "tagdesc"
		case "PORT": return "portdesc"
		case "TECH": return "technology"
		default: return s
	}
}
func StartOperatorSameTable(item e.CommandSameTable) (bool, string) {
	if(len(item.Command) == 0){ return false, "OR" }
	if(len(item.Command[0].CommandPatern) == 0){ return false, "OR" }
	retVal := strings.ToUpper(GetTokenValue(item.Command[0].CommandPatern[0]))
	isOperator :=func(s string) bool {
		switch(s){
		case "AND": return true
		case "OR": return true
		default: return false
		}
	}(retVal)
	if(!isOperator){ retVal = "OR"}
	return isOperator, retVal
}
func CreateBaseSqlToSelect(item e.CommandSameTable) string {
	tableListName := getTableListFromBaseTable(item.Table)
	tableCompareId := getColumnNameIdFromTable(item.Table)
	selectVal := "`%s` l INNER JOIN `%s` g ON l.`%s` = g.`%s` WHERE %s GROUP BY `ipaddress` HAVING COUNT(*) >= 1"
	whereSql := createSameTableSql(item)
	return (fmt.Sprintf(selectVal, tableListName, item.Table, tableCompareId, tableCompareId, whereSql))
}
