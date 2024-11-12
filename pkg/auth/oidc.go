// SPDX-FileCopyrightText: 2024 Siemens AG
// SPDX-FileContributor: Dearsh Oberoi <dearsh.oberoi@siemens.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/fossology/LicenseDb/pkg/db"
	"github.com/fossology/LicenseDb/pkg/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"gorm.io/gorm/clause"
)

var OidcConfig *oauth2.Config

var Jwks keyfunc.Keyfunc

// OidcLogin handles the OIDC login
//
//	@Summary		Handles the OIDC Login
//	@Description	Handles the OIDC Login
//	@Id				OidcLogin
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Success		307	{string}	string				"Temporary redirect to the oidc provider login page"
//	@Failure		500	{object}	models.LicenseError	"Failed to login"
//	@Router			/oidc/login [get]
func OidcLogin(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}
	session := sessions.Default(c)
	session.Set(state, state)
	session.Save()
	url := OidcConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// OidcCallback Handle the OAuth callback and retrieve token
//
//	@Summary		Handle the OAuth callback and retrieve token
//	@Description	Handle the OAuth callback and retrieve token
//	@Id				OidcCallback
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	object{token=string}	"JWT token"
//	@Failure		500	{object}	models.LicenseError		"Failed to login"
//	@Router			/oidc/callback [get]
func OidcCallback(c *gin.Context) {
	session := sessions.Default(c)
	retrievedStatus := c.Query("state")
	sentStatus := session.Get(retrievedStatus)
	if sentStatus == nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     "Something went wrong",
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}
	session.Delete(sentStatus)
	session.Save()

	code := c.Query("code")
	ctx := context.Background()
	token, err := OidcConfig.Exchange(ctx, code)
	if err != nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}

	rawIdToken := token.Extra("id_token")
	if rawIdToken == nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     "Something went wrong",
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}
	idToken := rawIdToken.(string)

	parsedToken, err := jwt.Parse(idToken, Jwks.Keyfunc)
	if err != nil || !parsedToken.Valid {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     "Something went wrong",
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}

	sub := claims["sub"].(string)
	iss := claims["iss"].(string)

	var user, newUser models.User
	user = models.User{
		Username:  claims["email"].(string),
		Userlevel: "USER",
		OidcSub:   &sub,
		OidcIss:   &iss,
	}

	result := db.DB.
		Where(&models.User{Username: user.Username}).
		FirstOrCreate(&user)

	if result.Error != nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Something went wrong",
			Error:     "Something went wrong",
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}

	if result.RowsAffected == 0 {
		if user.OidcSub != nil {
			if *user.OidcSub != sub {
				er := models.LicenseError{
					Status:    http.StatusInternalServerError,
					Message:   "Something went wrong",
					Error:     "Something went wrong",
					Path:      c.Request.URL.Path,
					Timestamp: time.Now().Format(time.RFC3339),
				}
				c.JSON(http.StatusInternalServerError, er)
				return
			}
		} else {
			// TODO: Endpoints for user update, delete and adding changelogs
			newUser = models.User{
				Id:      user.Id,
				OidcSub: &sub,
				OidcIss: &iss,
			}
			newUser.Id = user.Id
			if err := db.DB.Clauses(clause.Returning{}).Updates(&newUser).Error; err != nil {
				er := models.LicenseError{
					Status:    http.StatusInternalServerError,
					Message:   "Failed to login",
					Error:     err.Error(),
					Path:      c.Request.URL.Path,
					Timestamp: time.Now().Format(time.RFC3339),
				}
				c.JSON(http.StatusInternalServerError, er)
				return
			}
			user = newUser
		}
	}

	appToken, err := generateToken(user)
	if err != nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Failed to login",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": appToken})
}

// Generate a random `state` string
func generateState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.New("error generating random state")
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
