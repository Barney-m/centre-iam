package server

import (
	"centre/config"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var DB *gorm.DB

func LoadConfig(c chan error) {
	err := config.LoadConfig()

	if err != nil {
		c <- err
	}

	c <- nil
}

func ConnectDB(c chan error) {
	dbURL := config.Config.DatabaseUrl

	var err error
	DB, err = gorm.Open(mysql.Open(dbURL), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "centre.",
			SingularTable: true,
		},
	})

	if err != nil {
		c <- err
		close(c)
	}

	c <- nil
	close(c)
}
