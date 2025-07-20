package Utils
import (
	"fmt"
	"log"
	e "github.com/oreki9/shotan/Entity"
	"database/sql"
)
func createSqlCheckCommand(isFirstItem bool, tableName string, paternIndex int, columnName string, value string) string {
	sqlPatern := []string{
		"AND %s.%s LIKE '%%%s%%' ",
		"AND %s.title LIKE '%%%s%%' OR %s.value LIKE '%%%s%%' ",
		"AND %s.title LIKE '%%%s%%' AND %s.value LIKE '%%%s%%' ",
		"OR %s.%s LIKE '%%%s%%' ",
		"OR %s.title LIKE '%%%s%%' OR %s.value LIKE '%%%s%%' ",//4
		"OR %s.title LIKE '%%%s%%' AND %s.value LIKE '%%%s%%' ",
		"%s.%s LIKE '%%%s%%' ",//6
		"%s.title LIKE '%%%s%%' OR %s.value LIKE '%%%s%%' ",
		"%s.title LIKE '%%%s%%' AND %s.value LIKE '%%%s%%' ",
		
		"AND %s.title LIKE '%%%s%%'",//9
		"OR %s.title LIKE '%%%s%%'",
		"%s.title LIKE '%%%s%%'",
	}
	getIndex := func(isFirstCheck bool, idx int) int {
		if(idx>=0 && idx<=3){
			if(isFirstCheck) { return 7 } else { return 1}
		}else if(idx>3 && idx<=7){
			if(isFirstCheck) { return 8 } else { return 2}
		}else if(idx>7 && idx<=15){
			if(isFirstCheck) { 
				if(tableName == "tagdesc"){ return 11 }else{ return 7 }
			} else { 
				if(tableName == "tagdesc"){ return 9 }else{ return 1 }
			}
		}else if(idx>15 && idx<=19){
			if(isFirstCheck) { 
				if(tableName == "tagdesc"){ return 11 } else { return 7 } 
			} else { 
				if(tableName == "tagdesc"){ return 10 } else { return 4 } 
			}
		}else if(idx>19 && idx<=23){
			if(isFirstCheck) { return 7 } else { return 4}
		}else if(idx>23 && idx<=31){
			// fmt.Println("chck tag desc")
			if(isFirstCheck) {
				if(tableName == "tagdesc"){ return 11 }else{ return 5 } 
			} else {
				if(tableName == "tagdesc"){ return 10 }else{ return 4 } 
			}
		}else if(idx>31 && idx<=35){
			return 6
		}else if(idx>35 && idx<=38){
			return 8
		}else if(idx>39 && idx<=42){
			if(tableName == "tagdesc"){ return 11 }else{ return 7 } 
		}else{ return -1 }
    }
	isUsingColumn := func(idx int) bool {
		if(idx>31 && idx<=35){
			return true
		}else if(idx>35 && idx<=38){
			return true
		}else{
			return false
		}
	}(paternIndex)
	resultIndex := getIndex(isFirstItem, paternIndex)
	if(resultIndex == -1){ return ""}
	isPassValue := func(checkInt int) int {
		switch(checkInt){
		case 1: return 4
		case 2: return 4
		case 4: return 4
		case 5: return 4
		case 7: return 4

		case 8: return 4

		case 9: return 2
		case 10: return 2
		case 11: return 2
		default: return 3
		}
	}(resultIndex)
	// if(isFourValue && !isFirstItem){ because when info.country = kaza is error
	switch(isPassValue){
	case 4:
		firstValue := value
		if(isUsingColumn){
			firstValue = columnName
		}
		return fmt.Sprintf(sqlPatern[resultIndex], "g", firstValue, "g", value)
	case 2:
		return fmt.Sprintf(sqlPatern[resultIndex], "g", value)
	default:
		firstValue := value
		if(isUsingColumn){
			firstValue = columnName
		}
		return fmt.Sprintf(sqlPatern[resultIndex], "g", firstValue, value)
	}
}
func getColumnNameIdFromTable(tableName string) string {
	switch(tableName){
	case "portdesc": return "specificportid"
	case "generalinfo": return "generalinfoId"
	case "vulndesc": return "vulnid"
	case "tagdesc": return "tagid"
	case "technology": return "techid"
	default: return ""
	}
}
func getTableCompareIdTable(tableName string) string {
	switch(tableName){
	case "portdesc": return "listport"
	case "generalinfo": return "listgeneralinfo"
	case "vulndesc": return "listvuln"
	case "tagdesc": return "listtag"
	case "technology": return "listtech"
	default: return ""
	}
}
func getTableListFromBaseTable(tableName string) string {
	switch(tableName){
	case "portdesc": return "listport"
	case "generalinfo": return "listgeneralinfo"
	case "vulndesc": return "listvuln"
	case "tagdesc": return "listtag"
	case "technology": return "listtech"
	default: return ""
	}
}

func normalizeEqualString(str string) string {
	switch(str){
	case "=": return "="
	case ":": return "="
	default: return str
	}
}
// return isInPatern, paternIndex, isComplete
var GetIndexPaternWithAllTable = 42//len(checkPatern)-2
func CheckPaternToken(arrToken []e.TokenPos) (bool, int, bool) {
	checkPatern := [][]string{
		{"AND", "CUSTOM", ".", "CUSTOM", "=", "IDENT"},//0
		{"AND", "CUSTOM", ".", "CUSTOM", "=", "TEXTUAL"},
		{"AND", "CUSTOM", ".", "CUSTOM", "=", "INTEGER"},
		{"AND", "CUSTOM", ".", "CUSTOM", "=", "DECIMAL"},
		{"AND", "CUSTOM", ".", "IDENT", "=", "IDENT"},
		{"AND", "CUSTOM", ".", "IDENT", "=", "TEXTUAL"},
		{"AND", "CUSTOM", ".", "IDENT", "=", "INTEGER"},
		{"AND", "CUSTOM", ".", "IDENT", "=", "DECIMAL"},//7
		
		{"AND", "CUSTOM", "=", "IDENT"},//8
		{"AND", "CUSTOM", "=", "IDENT"},
		{"AND", "CUSTOM", "=", "TEXTUAL"},
		{"AND", "CUSTOM", "=", "TEXTUAL"},
		{"AND", "CUSTOM", "=", "INTEGER"},
		{"AND", "CUSTOM", "=", "INTEGER"},
		{"AND", "CUSTOM", "=", "DECIMAL"},
		{"AND", "CUSTOM", "=", "DECIMAL"},//15

		{"OR", "CUSTOM", ".", "CUSTOM", "=", "IDENT"},//16
		{"OR", "CUSTOM", ".", "CUSTOM", "=", "TEXTUAL"},
		{"OR", "CUSTOM", ".", "CUSTOM", "=", "INTEGER"},
		{"OR", "CUSTOM", ".", "CUSTOM", "=", "DECIMAL"},
		{"OR", "CUSTOM", ".", "IDENT", "=", "IDENT"},
		{"OR", "CUSTOM", ".", "IDENT", "=", "TEXTUAL"},
		{"OR", "CUSTOM", ".", "IDENT", "=", "INTEGER"},
		{"OR", "CUSTOM", ".", "IDENT", "=", "DECIMAL"},//23

		{"OR", "CUSTOM", "=", "IDENT"},
		{"OR", "CUSTOM", "=", "IDENT"},
		{"OR", "CUSTOM", "=", "TEXTUAL"},
		{"OR", "CUSTOM", "=", "TEXTUAL"},
		{"OR", "CUSTOM", "=", "INTEGER"},
		{"OR", "CUSTOM", "=", "INTEGER"},
		{"OR", "CUSTOM", "=", "DECIMAL"},
		{"OR", "CUSTOM", "=", "DECIMAL"},//31

		{"CUSTOM", ".", "CUSTOM", "=", "IDENT"},//32
		{"CUSTOM", ".", "CUSTOM", "=", "TEXTUAL"},
		{"CUSTOM", ".", "CUSTOM", "=", "INTEGER"},
		{"CUSTOM", ".", "CUSTOM", "=", "DECIMAL"},//35
		{"CUSTOM", ".", "IDENT", "=", "IDENT"},
		{"CUSTOM", ".", "IDENT", "=", "TEXTUAL"},
		{"CUSTOM", ".", "IDENT", "=", "INTEGER"},
		{"CUSTOM", ".", "IDENT", "=", "DECIMAL"},// 38
		{"CUSTOM", "=", "TEXTUAL"},
		{"CUSTOM", "=", "IDENT"},
		{"CUSTOM", "=", "INTEGER"},
		{"CUSTOM", "=", "DECIMAL"},//42
		{"IDENT"},
		{"TEXTUAL"},
		{"INTEGER"},
		{"DECIMAL"},
	}
	for idx, arrTokenCheck := range checkPatern {
		isComplete := false
		if len(arrToken) > len(arrTokenCheck) {
			continue
		}
		isContinue := false
		for i, tokenCheck := range arrToken {
			tokenStr := normalizeEqualString(getIsCustomKeyword(fmt.Sprintf("%s", tokenCheck.Tok)))
			if(tokenStr != arrTokenCheck[i]) { 
				isContinue = true
				break
			}
		}
		if(isContinue){
			continue
		}
		if len(arrToken) == len(arrTokenCheck) {
			isComplete = true
		}
		return true, idx, isComplete
	}
	return false, -1, false
}
func GetDetailIpAddress(db *sql.DB, ipaddress string, filterIdx []int) e.IpInfoLinkdataHolder {
	returnSqlCommand := [][]string {
		{"`generalinfoid`", "`listgeneralinfo`"},
		{"`tagid`", "`listtag`"},
		{"`vulnid`", "`listvuln`"},
		{"`techid`", "`listtech`"},
		{"`specificportid`", "`listport`"},
	}// return column name and table name
	ipinfoHolder := e.IpInfoLinkdataHolder{
		IPAddress: ipaddress,
		Tagdata: []e.TagDesc{},
		Portdata: []e.PortDesc{},
		Geninfo: []e.GeneralInfo{},
		Vulndata: []e.VulnDesc{},
		Techdata: []e.Technology{},
	}
	for idx, arrVal := range returnSqlCommand {
		var isContinue = false
		for _, checkIdx := range filterIdx {
			if(checkIdx == idx){
				isContinue = true
			}
		}
		if(isContinue){
			continue
		}
		var selectGenInfo = fmt.Sprintf("SELECT %s FROM %s WHERE `ipaddress` like '%s'", arrVal[0], arrVal[1], ipaddress)
		isSelectError, SelectRes, _ := GetSQLData(db, selectGenInfo)
		if(!isSelectError){
			defer SelectRes.Close()
			for SelectRes.Next() {
				idSelect := 0
				err := SelectRes.Scan(&idSelect)
				if err != nil { log.Fatal(err) }
				GetBasicData(db, &ipinfoHolder, idx, idSelect)
			}
		}
	}
	return ipinfoHolder
}
func DeleteIpAddress(db *sql.DB, ipAddress string){
	returnSqlCommand := [][]string {
		{"generalinfo", "listgeneralinfoid", "listgeneralinfo"},
		{"tagdesc", "listtagid", "listtag"},
		{"vulndesc", "listvulnid", "listvuln"},
		{"technology", "listtechid", "listtech"},
		{"portdesc", "listportid", "listport"},
	}// return column name and table name
	var selectGenInfo = fmt.Sprintf("SELECT `listgeneralinfoid`, `listtagid`, `listvulnid`, `listtechid`, `listportid` FROM `ipinfolink` WHERE `ipaddress` like '%s'", ipAddress)
	isSelectError, SelectRes, _ := GetSQLData(db, selectGenInfo)
	if(!isSelectError){
		for SelectRes.Next() {
			var dataItem e.IpInfoLink
			err := SelectRes.Scan(&dataItem.ListGeneralInfoId, &dataItem.ListTagId, &dataItem.ListVulnId, &dataItem.ListTechId, &dataItem.ListPortId)
			if err != nil { log.Fatal(err) }
			for idx, arrVal := range returnSqlCommand {
				idxSqlCmd := ""
				switch(idx){
				case 0: idxSqlCmd = dataItem.ListGeneralInfoId
				break;
				case 1: idxSqlCmd = dataItem.ListTagId	
				break;
				case 2: idxSqlCmd = dataItem.ListVulnId
				break;
				case 3: idxSqlCmd = dataItem.ListTechId	
				break;
				case 4: idxSqlCmd = dataItem.ListPortId	
				break;
				default: break;
				}
				if idxSqlCmd != "" {
					deleteListData(db, idxSqlCmd, arrVal[2])
					var deleteSqlCmd = fmt.Sprintf("DELETE FROM `%s` WHERE `%s` like %s", arrVal[2], arrVal[1], idxSqlCmd)
					ExecuteSQLData(db, deleteSqlCmd)
					// defer SelectDelRes.Close()
				}
			}
		}
	}
	var deleteSqlCmd = fmt.Sprintf("DELETE FROM `ipinfolink` WHERE `ipaddress` like %s", ipAddress)
	ExecuteSQLData(db, deleteSqlCmd)
	defer SelectRes.Close()
}
// i dont want to make code more difficult so just base
func deleteListData(db *sql.DB, ownerSpecificId string, tableNameOwnerList string) {
	idxReqdata := 0
	switch(tableNameOwnerList){
	case "listgeneralinfo":
		idxReqdata = 0
		break;
	case "listtag":
		idxReqdata = 1
		break;
	case "listvuln":
		idxReqdata = 2
		break;
	case "listtech":
		idxReqdata = 3
		break;
	case "listport":
		idxReqdata = 4
		break;
	}
	tableReqdata := [][]string {
		{"generalinfo", "generalinfoid", "listgeneralinfo", "listgeneralinfoid"},
		{"tagdesc", "tagid", "listtag", "listtagid"},
		{"vulndesc", "vulnid", "listvuln", "listvulnid"},
		{"technology", "techid", "listtech", "listtechid"},
		{"portdesc", "specificportid", "listport", "listportid"},
	}// return column name and table name
	var selectGenInfo = fmt.Sprintf("SELECT %s FROM `%s` WHERE `%s` = '%s'", tableReqdata[idxReqdata][1], tableNameOwnerList, tableReqdata[idxReqdata][3], ownerSpecificId)
	isSelectError, SelectRes, _ := GetSQLData(db, selectGenInfo)
	if(!isSelectError){
		for SelectRes.Next() {
			idxWilldelete := "0"
			err := SelectRes.Scan(&idxWilldelete)
			if err != nil { log.Fatal(err) }
			var deleteSqlCmd = fmt.Sprintf("DELETE FROM `%s` WHERE `%s` like %s", tableReqdata[idxReqdata][0], tableReqdata[idxReqdata][1], idxWilldelete)
			// if(true){ return; }// for test
			ExecuteSQLData(db, deleteSqlCmd)
			// defer DeleteRes.Close()
		}
	}
	// defer SelectRes.Close()
}
func GetBasicData(db *sql.DB, data *e.IpInfoLinkdataHolder, basedataIdx int, id int) {
	returnSqlCommand := [][]string {
		{"`generalinfoId`, `title`, `value`", "`generalinfo`", "`generalinfoId`"},
		{"`tagid`, `title`", "`tagdesc`", "`tagid`"},
		{"`vulnid`, `title`, `value`", "`vulndesc`", "`vulnid`"},
		{"`techid`, `title`, `value`", "`technology`", "`techid`"},
		{"`specificportid`, `title`, `value`", "`portdesc`", "`specificportid`"},
	}// return column name and table name
	var selectGenInfo = fmt.Sprintf("SELECT %s FROM %s WHERE %s = %d", returnSqlCommand[basedataIdx][0], returnSqlCommand[basedataIdx][1], returnSqlCommand[basedataIdx][2], id)
	isSelectError, SelectRes, _ := GetSQLData(db, selectGenInfo)
	// fmt.Println(selectGenInfo)
	if(!isSelectError){
		defer SelectRes.Close()
		for SelectRes.Next() {
			switch(basedataIdx){
			case 0:
				var dataItem e.GeneralInfo
				err := SelectRes.Scan(&dataItem.GeneralInfoId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.Geninfo = append(data.Geninfo, dataItem)
			case 1:
				var dataItem e.TagDesc
				err := SelectRes.Scan(&dataItem.TagId, &dataItem.Title)
				if err != nil { log.Fatal(err) }
				data.Tagdata = append(data.Tagdata, dataItem)
			case 2:
				var dataItem e.VulnDesc
				err := SelectRes.Scan(&dataItem.VulnId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.Vulndata = append(data.Vulndata, dataItem)
			case 3:
				var dataItem e.Technology
				err := SelectRes.Scan(&dataItem.TechId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.Techdata = append(data.Techdata, dataItem)
			case 4:
				var dataItem e.PortDesc
				err := SelectRes.Scan(&dataItem.SpecificPortId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.Portdata = append(data.Portdata, dataItem)
			default: break;
			}
		}
	} 
}
func GetSQLData(db *sql.DB,query string) (bool, *sql.Rows, error) {
	// fmt.Println(query)
	res, err := db.Query(query)
	var isError bool = false
    if err != nil {
        isError = true
    }
	return isError,res,err
}
func ExecuteSQLData(db *sql.DB,query string) (bool, sql.Result, error) {
	// fmt.Println(query)
	res, err := db.Exec(query)
	var isError bool = false
    if err != nil {
        isError = true
    }
	return isError,res,err
}
