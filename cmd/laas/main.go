// SPDX-FileCopyrightText: 2023 Kavya Shukla <kavyuushukla@gmail.com>
// SPDX-FileCopyrightText: 2023 Siemens AG
// SPDX-FileContributor: Gaurav Mishra <mishra.gaurav@siemens.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"flag"
	"log"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"gorm.io/gorm/clause"

	_ "github.com/dave/jennifer/jen"
	_ "github.com/fossology/LicenseDb/cmd/laas/docs"
	"github.com/fossology/LicenseDb/pkg/api"
	"github.com/fossology/LicenseDb/pkg/auth"
	"github.com/fossology/LicenseDb/pkg/db"
	"github.com/fossology/LicenseDb/pkg/models"
	"github.com/fossology/LicenseDb/pkg/utils"
)

// declare flags to input the basic requirement of database connection and the path of the data file
var (
	// argument to enter the name of database host
	dbhost = flag.String("host", "localhost", "host name")
	// port number of the host
	port = flag.String("port", "5432", "port number")
	// argument to enter the database user
	user = flag.String("user", "fossy", "user name")
	// name of database to be connected
	dbname = flag.String("dbname", "fossology", "database name")
	// password of the database
	password = flag.String("password", "fossy", "password")
	// path of data file
	datafile = flag.String("datafile", "licenseRef.json", "datafile path")
	// auto-update the database
	populatedb = flag.Bool("populatedb", false, "boolean variable to update database")
)

func main() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	if os.Getenv("CLIENT_ID") == "" || os.Getenv("CLIENT_SECRET") == "" || os.Getenv("REDIRECT_URL") == "" ||
		os.Getenv("AUTH_URL") == "" || os.Getenv("TOKEN_URL") == "" || os.Getenv("JWKS_URI") == "" {
		log.Fatalf("Missing OIDC configuration values in .env file")
	}

	// OIDC configuration
	auth.OidcConfig = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("AUTH_URL"),
			TokenURL: os.Getenv("TOKEN_URL"),
		},
	}

	auth.Jwks, err = keyfunc.NewDefault([]string{os.Getenv("JWKS_URI")}) // Context is used to end the refresh goroutine.
	if err != nil {
		log.Fatalf("Failed to create a keyfunc.Keyfunc from the oidc provider's URL: %s", err)
	}

	flag.Parse()

	db.Connect(dbhost, port, user, dbname, password)

	if err := db.DB.AutoMigrate(&models.LicenseDB{}); err != nil {
		log.Fatalf("Failed to automigrate database: %v", err)
	}

	if err := db.DB.AutoMigrate(&models.User{}); err != nil {
		log.Fatalf("Failed to automigrate database: %v", err)
	}

	if err := db.DB.AutoMigrate(&models.Audit{}); err != nil {
		log.Fatalf("Failed to automigrate database: %v", err)
	}

	if err := db.DB.AutoMigrate(&models.ChangeLog{}); err != nil {
		log.Fatalf("Failed to automigrate database: %v", err)
	}

	if err := db.DB.AutoMigrate(&models.Obligation{}); err != nil {
		log.Fatalf("Failed to automigrate database: %v", err)
	}

	DEFAULT_OBLIGATION_TYPES := []*models.ObligationType{
		{Type: "OBLIGATION"},
		{Type: "RISK"},
		{Type: "RESTRICTION"},
		{Type: "RIGHT"},
	}
	DEFAULT_OBLIGATION_CLASSIFICATIONS := []*models.ObligationClassification{
		{Classification: "GREEN", Color: "#00FF00"},
		{Classification: "WHITE", Color: "#FFFFFF"},
		{Classification: "YELLOW", Color: "#FFDE21"},
		{Classification: "RED", Color: "#FF0000"},
	}

	if err := db.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(DEFAULT_OBLIGATION_TYPES).Error; err != nil {
		log.Fatalf("Failed to seed database with default obligation types: %s", err.Error())
	}

	if err := db.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(DEFAULT_OBLIGATION_CLASSIFICATIONS).Error; err != nil {
		log.Fatalf("Failed to seed database with default obligation classifications: %s", err.Error())
	}

	if *populatedb {
		utils.Populatedb(*datafile)
	}

	r := api.Router()

	if err := r.Run(); err != nil {
		log.Fatalf("Error while running the server: %v", err)
	}
}
