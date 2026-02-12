package main

import (
	"log"
	"os"
	"time"

	oauth2 "github.com/benjamesfleming/pocketbase-ext-oauth2"
	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()
	app.RootCmd.ParseFlags(os.Args[1:])

	oauth2.MustRegister(
		app,
		&oauth2.Config{
			BaseConfig: &oauth2.BaseConfig{
				AccessTokenLifespan:   time.Hour,
				AuthorizeCodeLifespan: time.Minute * 15,
				EnforcePKCE:           true,
				RefreshTokenScopes:    []string{}, // All scopes are allowed for refresh tokens
			},
			PathPrefix:                             "/oauth2",
			UserCollection:                         "users",
			EnableRFC7591DynamicClientRegistration: true,
			EnableRFC9728ProtectedResourceMetadata: true,
		},
	)

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
