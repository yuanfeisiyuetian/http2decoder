package main

import (
	_ "github.com/Go-SQL-Driver/MySQL"
	"database/sql"
)

func Writetomysql(jb JsonBody)  {
	db, err := sql.Open("mysql", "root:root@tcp(10.112.137.57:3306)/5GC?charset=utf8")
	if err != nil {
		panic(err)
	}
	stmt,err := db.Prepare("insert into traffic_field(c1,c2,c3,c4,c5,c6,c7,c8)values(?,?,?)");
	stmt.Close()
}