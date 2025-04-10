package Entity
import (
	"fmt"
	"github.com/oreki9/lexer"
	// p "github.com/oreki9/shotan/Utils"
)
// type OptionalInt struct {
// 	Value int
// 	Valid bool
// }
type IPAddressGenInfo struct {
	Ipaddress string `json:"ipaddress"`
	Geninfo []GeneralInfo `json:"geninfo"`
}
type ListIpAddressObj struct {
	MaxPage string `json:"maxPage"`
	Index string `json:"index"`
	List []IPAddressGenInfo `json:"list"`
}
type Command struct {// example "AND table.column like `%value%` "
	CommandPatern []TokenPos
	IndexPatern int
}
type CommandSameTable struct {// example "AND table1.column like `%value1%` AND table2.column like `%value2%`"
	Table string
	Command []Command
}
type TokenPos struct {// ex: IDENT, 0, INFO
	Tok lexer.Token
	Pos lexer.Pos
	Lit string
}
type IpInfoLink struct {
	Id int
	IPAddress string
	ListTagId string
	ListGeneralInfoId string
	ListVulnId string
	ListTechId string
	ListPortId string
}
type IpInfoLinkdataHolder struct {
	IPAddress string `json:"ipaddress"`
	Tagdata []TagDesc `json:"taglist"`
	Portdata []PortDesc `json:"portlist"`
	Geninfo []GeneralInfo `json:"general"`
	Vulndata []VulnDesc `json:"vulnlist"`
	Techdata []Technology `json:"techlist"`
}
type CheckAllValidData struct {
	IsPortdescValid bool
	IsGeneralinfoValid bool
	IsVulndescValid bool
	IsTagdescValid bool
	IsTechnologyValid bool
}
func (d CheckAllValidData) IsValid() bool {
	fmt.Println(d)
	return d.IsPortdescValid && d.IsGeneralinfoValid && d.IsVulndescValid && d.IsTagdescValid && d.IsTechnologyValid
}
type ListPort struct {
	Id int
	ListPortId int
	IPAddress string
	SpecificPortId int
}
type ListTech struct {
	Id int
	ListTechId int
	IPAddress string
	TechId int
}
type ListVuln struct {
	Id int
	ListVulnId int
	IPAddress string
	VulnId int
}
type ListTag struct {
	Id int
	ListTagId int
	IPAddress string
	TagId int
}
type ListGeneralInfo struct {
	id int
	ListGeneralInfoId int
	IPAddress string
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