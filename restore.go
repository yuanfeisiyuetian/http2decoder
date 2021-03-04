package main

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

var (
	userName  string = "root"
	password  string = "root"
	ipAddrees string = "10.112.137.57"
	port      int    = 3306
	dbName    string = "5GC"
)

//type HTTP2 struct {
//	ID       int    `db:"id"`
//	Time     string `db:"time"`
//	Srcip    string `db:"srcip"`
//	Srcport  string `db:"srcport"`
//	Desip    string `db:"desip"`
//	Desport  string `db:"desport"`
//	Url      string `db:"url"`
//	Method   string `db:"method"`
//	Status   string `db:"status"`
//	Reqheader string `db:"reqheader"`
//	Reqbody   string `db:"reqbody"`
//	Resheader string `db:"resheader"`
//	Resbody   string `db:"resbody"`
//
//}
var Db *sqlx.DB

func ConnectMysql() *sqlx.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", userName, password, ipAddrees, port, dbName)
	Db, err := sqlx.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("mysql connect failed, detail is [%v]", err.Error())
	}
	return Db
}
