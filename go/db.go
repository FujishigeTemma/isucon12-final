package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
)

func connectDB(batch bool) (*sqlx.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=%s&multiStatements=%t&interpolateParams=true",
		getEnv("ISUCON_DB_USER", "isucon"),
		getEnv("ISUCON_DB_PASSWORD", "isucon"),
		getEnv("ISUCON_DB_HOST", "127.0.0.1"),
		getEnv("ISUCON_DB_PORT", "3306"),
		getEnv("ISUCON_DB_NAME", "isucon"),
		"Asia%2FTokyo",
		batch,
	)
	dbx, err := sqlx.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return dbx, nil
}

func waitDB(db *sqlx.DB) {
	for {
		err := db.Ping()
		if err == nil {
			return
		}

		log.Printf("Failed to ping DB: %s", err)
		log.Println("Retrying...")
		time.Sleep(time.Second)
	}
}

func pollDB(db *sqlx.DB) {
	for {
		err := db.Ping()
		if err != nil {
			log.Printf("Failed to ping DB: %s", err)
		}

		time.Sleep(time.Second)
	}
}
