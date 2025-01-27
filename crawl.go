package main

import (
	// "encoding/json"
	"flag"
	"fmt"
	"github.com/gocolly/colly"
	"log"
	"math/rand"
	"time"
	// "strings"

	"database/sql"
    _ "github.com/go-sql-driver/mysql"
)

type IpInfoLink struct {
	Id int
	ListTagId string
	ListGeneralInfoId string
	ListVulnId string
	ListTechId string
	ListPortId string
}
type IpInfoLinkdataHolder struct {
	tagdata []TagDesc
	portdata []PortDesc
	geninfo []GeneralInfo
	vulndata []VulnDesc
	techdata []Technology
}
type CheckAllValidData struct {
	isPortdescValid bool
	isGeneralinfoValid bool
	isVulndescValid bool
	isTagdescValid bool
	isTechnologyValid bool
}
func (d CheckAllValidData) isValid() bool {
	return d.isPortdescValid && d.isGeneralinfoValid && d.isVulndescValid && d.isTagdescValid && d.isTechnologyValid
}
type ListPort struct {
	Id int
	ListPortId int
	SpecificPortId int
}
type ListTech struct {
	Id int
	ListTechId int
	TechId int
}
type ListVuln struct {
	Id int
	ListVulnId int
	VulnId int
}
type ListTag struct {
	Id int
	ListTagId int
	TagId int
}
type ListGeneralInfo struct {
	id int
	ListGeneralInfoId int
	GeneralInfoId int
}
type TagDesc struct {
	TagId int
	Title string
}
type PortDesc struct {
	SpecificPortId int// even title is same but value desc is not same
	Title string
	Value string
}
type GeneralInfo struct {
	GeneralInfoId int
	Title string
	Value string
}
type VulnDesc struct {
	VulnId int
	Title string
	Value string
}
type Technology struct {
	TechId int
	Title string
	Value string
}
func main() {
	ipaddress := flag.String("ipaddress", "109.206.245.168", "ip address target")
	flag.Parse()
	
	db, err := sql.Open("mysql", "root:@(127.0.0.1:3306)/shotan")
    defer db.Close()
	if err != nil {
		log.Fatal(err)
    }
	if (checkAllTable(db, "shotan")){
		fmt.Println("database is not perfect, now in progress")
	}else{
		fmt.Println("database is perfect")
		fmt.Println(*ipaddress)
		// crawl(db, *ipaddress)
	}
}

func crawl(db *sql.DB, ipaddress string) {
	c := colly.NewCollector(
		colly.AllowedDomains(),
	)
	checkAllDataComplete := CheckAllValidData{
		isPortdescValid: false,
		isGeneralinfoValid: false,
		isVulndescValid: false,
		isTagdescValid: false,
		isTechnologyValid: false,
	}
	ipinfoHolder := IpInfoLinkdataHolder{
		tagdata: []TagDesc{},
		portdata: []PortDesc{},
		geninfo: []GeneralInfo{},
		vulndata: []VulnDesc{},
		techdata: []Technology{},
	}
	// get data for table generalinfo
	c.OnHTML(".card.card-yellow.card-padding > .table", func(e *colly.HTMLElement) {
		// listNewGenInfo := []GeneralInfo{}
		e.ForEach("tr", func(_ int, kf *colly.HTMLElement) {
			var domValue = kf.ChildTexts("td")
			var title = domValue[0]
			var desc = domValue[1]
			newGenInfo := GeneralInfo{
				GeneralInfoId: 0,
				Title: title,
				Value: desc,
			}
			ipinfoHolder.geninfo = append(ipinfoHolder.geninfo, newGenInfo) 
			// listNewGenInfo = append(listNewGenInfo, newGenInfo)
		})
		checkAllDataComplete.isGeneralinfoValid = true
		checkAllComplete(db, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(ipinfoHolder.geninfo)
		// fmt.Println("check 1")
	})
	
	// get data for tagdesc table
	c.OnHTML("div #tags", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".tag")
		for _, tagStr := range arrayDescVal {
			ipinfoHolder.tagdata = append(ipinfoHolder.tagdata, TagDesc{
				TagId: 0,
				Title: tagStr,
			})
		}
		checkAllDataComplete.isTagdescValid = true
		checkAllComplete(db, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(arrayDescVal)
		// fmt.Println("")
	})
	
	// get data for portdesc table
	c.OnHTML(".six.columns", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".card.card-padding.banner")
		var arrayTitle = e.ChildTexts(".card.card-light-blue.card-padding > #ports > a")
		// var countU = 0
		for idx, value := range arrayTitle {
			// if(countU>0) { break; }
			var searchDOM = fmt.Sprintf("#%s > span", value)
			var elementWithID = e.DOM.Find(searchDOM)
			if elementWithID.Length() > 0 {
				var portTitle = elementWithID.Text()
				var portDesc = arrayDescVal[idx]
				ipinfoHolder.portdata = append(ipinfoHolder.portdata, PortDesc{
					SpecificPortId: 0,
					Title: portTitle,
					Value: portDesc,
				})
				// fmt.Println(elementWithID.Text())
			}
			// fmt.Println(arrayDescVal[idx])
			// countU+=1;
		}
		checkAllDataComplete.isPortdescValid = true
		checkAllComplete(db, checkAllDataComplete, ipinfoHolder)
		// fmt.Println("")
		// fmt.Println(fmt.Sprintf("%d check %d", len(arrayDescVal), len(arrayTitle)))
	})

	// get data for technology table
	c.OnHTML(".card.card-padding.card-purple", func(e *colly.HTMLElement) {
		e.ForEach(".category", func(_ int, kf *colly.HTMLElement) {
			var titleTech = kf.ChildText(".category-heading")
			var listTechUsed = kf.ChildText(".technology")//it have to used kf.ChildTexts(".technology")
			ipinfoHolder.techdata = append(ipinfoHolder.techdata, Technology{
				TechId: 0,
				Title: titleTech,
				Value: listTechUsed,
			})
			// fmt.Println("")
		})
		checkAllDataComplete.isTechnologyValid = true
		checkAllComplete(db, checkAllDataComplete, ipinfoHolder)
		fmt.Println("check 2")
	})
	
	// get data for vulndesc table
	c.OnHTML(".card.card-red.card-padding > .table", func(e *colly.HTMLElement) {
		var countCheck = 0
		e.ForEach("tr", func(_ int, kf *colly.HTMLElement) {
			if(countCheck > 0){ return; }
			countCheck+=1;
			var valueDom = kf.ChildTexts("td")
			fmt.Println(valueDom)
			var titleVuln = valueDom[0]
			var descVuln = valueDom[1]
			ipinfoHolder.vulndata = append(ipinfoHolder.vulndata, VulnDesc{
				VulnId: 0,
				Title: titleVuln,
				Value: descVuln,
			})
			
		})
		fmt.Println("check 1")
		checkAllDataComplete.isVulndescValid = true
		checkAllComplete(db, checkAllDataComplete, ipinfoHolder)
	})
	
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting: ", r.URL.String())
	})

	// uncomment below line if you enable Async mode
	// c.Wait()
	startUrl := fmt.Sprintf("http://localhost/shotan/file_%s.html", ipaddress)
	print("start")
	c.Visit(startUrl)
}
func checkAllComplete(db *sql.DB, checkData CheckAllValidData, ipinfoHolder IpInfoLinkdataHolder) (bool) {
	if (checkData.isValid()){
		insertAllData(db, ipinfoHolder.tagdata, ipinfoHolder.portdata, ipinfoHolder.geninfo, ipinfoHolder.vulndata, ipinfoHolder.techdata)
	}
	return false
}
func deleteAllTable(db *sql.DB) (bool) {
	isDeleteError1, _, _ := getSQLData(db, "DROP TABLE `ipinfolink`;")
	isDeleteError2, _, _ := getSQLData(db, "DROP TABLE `portdesc`;")
	isDeleteError3, _, _ := getSQLData(db, "DROP TABLE `generalinfo`;")
	isDeleteError4, _, _ := getSQLData(db, "DROP TABLE `vulndesc`;")
	isDeleteError5, _, _ := getSQLData(db, "DROP TABLE `tagdesc`;")
	isDeleteError6, _, _ := getSQLData(db, "DROP TABLE `technology`;")
	isDeleteError7, _, _ := getSQLData(db, "DROP TABLE `listgeneralinfo`;")
	isDeleteError8, _, _ := getSQLData(db, "DROP TABLE `listtag`;")
	isDeleteError9, _, _ := getSQLData(db, "DROP TABLE `listvuln`;")
	isDeleteError10, _, _ := getSQLData(db, "DROP TABLE `listtech`;")
	isDeleteError11, _, _ := getSQLData(db, "DROP TABLE `listport`;")
	return isDeleteError1 || isDeleteError2 || isDeleteError3 || isDeleteError4 || isDeleteError5 || isDeleteError6 || isDeleteError7 || isDeleteError8 || isDeleteError9 || isDeleteError10 || isDeleteError11
}
func insertAllData(db *sql.DB, tagdata []TagDesc, portdata []PortDesc, geninfo []GeneralInfo, vulndata []VulnDesc, techdata []Technology) (bool) {
	listGeneralInfoId, _ := CreateUniqueRandomID(db, "generalinfo", "listgeneralinfoid")
	// create random id for ListGeneralInfoId
	for _, item := range geninfo {
		geninfoid, isValid := insertGeneralInfo(db, item.Title, item.Value)
		if(isValid){
			insertListGenInfo(db, listGeneralInfoId, geninfoid)
		}
	}
	listtagid, _ := CreateUniqueRandomID(db, "listtag", "listtagid")
	for _, item := range tagdata {
		tagid, isValid := insertTagData(db, item.Title)
		if(isValid){
			insertListTag(db, listtagid, tagid)
		}
	}
	listportid, _ := CreateUniqueRandomID(db, "listport", "listportid")
	for _, item := range portdata {
		portid, isValid := insertPortDesc(db, item.Title, item.Value)
		if(isValid){
			insertListPort(db, listportid, portid)
		}
	}
	listvulnid, _ := CreateUniqueRandomID(db, "listvuln", "listvulnid")
	for _, item := range vulndata {
		vulnid, isValid := insertVulnDesc(db, item.Title, item.Value)
		if(isValid){
			insertListVuln(db, listvulnid, vulnid)
		}
	}
	listtechid, _ := CreateUniqueRandomID(db, "listtech", "listtechid")
	for _, item := range techdata {
		techid, isValid := insertTechData(db, item.Title, item.Value)
		if(isValid){
			insertListTech(db, listtechid, techid)
		}
	}
	return insertIPInfo(db, listtagid, listGeneralInfoId, listvulnid, listtechid, listportid)
}
func insertIPInfo(db *sql.DB, listtagid int64, listgeneralinfoid int64, listvulnid int64, listtechid int64, listportid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `ipinfolink`(`listtagid`, `listgeneralinfoid`, `listvulnid`, `listtechid`, `listportid`) VALUES ('%d','%d','%d','%d','%d')", listtagid, listgeneralinfoid, listvulnid, listtechid, listportid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertPortDesc(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `portdesc`(`title`, `value`) VALUES ('%s','%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr)
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func insertGeneralInfo(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `generalinfo`(`title`, `value`) VALUES ('%s','%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr)
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func insertVulnDesc(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `vulndesc`(`title`, `value`) VALUES ('%s','%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr)
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func insertTagData(db *sql.DB, title string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `tagdesc`(`title`) VALUES ('%s')", title)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr)
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func insertTechData(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `technology`(`title`, `value`) VALUES ('%s', '%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr)
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func insertListGenInfo(db *sql.DB, listgeneralinfoid int64, generalinfoid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listgeneralinfo`(`listgeneralinfoid`, `generalinfoid`) VALUES ('%d','%d')", listgeneralinfoid, generalinfoid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListTag(db *sql.DB, listtagid int64, tagid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listtag`(`listtagid`, `tagid`) VALUES ('%d','%d')", listtagid, tagid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListVuln(db *sql.DB, listvulnid int64, vulnid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listvuln`(`listvulnid`, `vulnid`) VALUES ('%d','%d')", listvulnid, vulnid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListTech(db *sql.DB, listtechid int64, techid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listtech`(`listtechid`, `techid`) VALUES ('%d','%d')", listtechid, techid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListPort(db *sql.DB, listportid int64, specificportid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listport`(`listportid`, `specificportid`) VALUES ('%d','%d')", listportid, specificportid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func checkAllTable(db *sql.DB, dbName string) (bool) {
	var checkPortListVal = checkListPort(db,dbName) 
	var checkTechListVal = checkListTech(db, dbName) 
	var checkVulnListVal = checkListVuln(db, dbName) 
	var checkTagListVal = checkListTag(db, dbName) 
	var checkGenInfoListVal = checkListGeneralInfo(db, dbName)
	var checkListTable = checkPortListVal && checkTechListVal && checkVulnListVal && checkTagListVal && checkGenInfoListVal
	var checkTechnologyVal = checkTechnology(db, dbName)
	var checkTagDescVal = checkTagDesc(db, dbName)
	var checkVulnVal = checkVuln(db, dbName)
	var checkGeneralInfoVal = checkGeneralInfo(db, dbName)
	var checkPortVal = checkPort(db, dbName)
	var checkDataHolderTable = checkTechnologyVal && checkTagDescVal && checkVulnVal && checkGeneralInfoVal && checkPortVal
	var checkMainTable = checkIPInfoLink(db, dbName)
	return checkListTable && checkDataHolderTable && checkMainTable
}
func getSQLData(db *sql.DB,query string) (bool, *sql.Rows, error) {
	res, err := db.Query(query)
	var isError bool = false
    if err != nil {
        isError = true
    }
	return isError,res,err
}
func getSQLResultid(db *sql.DB,query string) (bool, int64, sql.Result, error) {
	result, err := db.Exec(query)
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

// create main table
func checkIPInfoLink(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "ipinfolink")){
		var createSQL = `CREATE TABLE ipinfolink (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listtagid INT(20) NOT NULL,
			listgeneralinfoid INT(20) NOT NULL,
			listvulnid INT(20) NOT NULL,
			listtechid INT(20) NOT NULL,
			listportid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
// create table info item
func checkPort(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "portdesc")){
		var createSQL = `CREATE TABLE portdesc (
			specificportid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (specificportid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, err := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}else{
			fmt.Println(err)
		}
	}
	return false
}
func checkGeneralInfo(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "generalinfo")){
		var createSQL = `CREATE TABLE generalinfo (
			generalinfoId INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (generalinfoId)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkVuln(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "vulndesc")){
		var createSQL = `CREATE TABLE vulndesc (
			vulnid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (vulnid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTagDesc(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "tagdesc")){
		var createSQL = `CREATE TABLE tagdesc (
			tagid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			PRIMARY KEY (tagid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTechnology(db *sql.DB, dbName string) (bool){
	if(!checkTable(db, dbName, "technology")){
		var createSQL = `CREATE TABLE technology (
			techid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (techid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
// create table list
func checkListGeneralInfo(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listgeneralinfo")){
		var createSQL = `CREATE TABLE listgeneralinfo (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listgeneralinfoid VARCHAR(255) NOT NULL,
			generalinfoid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListTag(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listtag")){
		var createSQL = `CREATE TABLE listtag (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listtagid INT(20) NOT NULL,
			tagid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListVuln(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listvuln")){
		var createSQL = `CREATE TABLE listvuln (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listvulnid INT(20) NOT NULL,
			vulnid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListTech(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listtech")){
		var createSQL = `CREATE TABLE listtech (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listtechid INT(20) NOT NULL,
			techid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListPort(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listport")){
		var createSQL = `CREATE TABLE listport (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listportid INT(20) NOT NULL,
			specificportid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTable(db *sql.DB, dbName string, tableName string) (bool) {
	var count int = 0
	var checktableStr = fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = "%s" AND table_name = "%s";`, dbName, tableName)
	isCheckTableError, CheckTableRes, err := getSQLData(db, checktableStr)
	if err != nil {
		fmt.Println(err)
	}
	if(!isCheckTableError){
		defer CheckTableRes.Close()
		CheckTableRes.Next()
		err := CheckTableRes.Scan(&count)
		if err != nil {
			log.Fatal(err)
		}
		return (count > 0)
	}
	return false
}
// GenerateRandomID creates a random integer ID
func GenerateRandomID() int64 {
	rand.Seed(time.Now().UnixNano())
	return rand.Int63n(1000000) // Generate a random number in a defined range
}

// CreateUniqueRandomID generates a random ID and ensures it's unique in the database
func CreateUniqueRandomID(db *sql.DB, tableName, columnName string) (int64, error) {
	for {
		randomID := GenerateRandomID()
		query := fmt.Sprintf("SELECT COUNT(*) FROM `%s` WHERE `%s` = ?", tableName, columnName)
		var count int
		err := db.QueryRow(query, randomID).Scan(&count)
		if err != nil {
			return 0, fmt.Errorf("failed to check ID existence: %w", err)
		}
		if count == 0 {
			return randomID, nil
		}
	}
}