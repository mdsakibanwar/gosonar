package main

import (
	"database/sql"
	"database/sql/driver"
)

func main() {
	var _ = sql.ErrConnDone
	var _ = driver.Bool
}
