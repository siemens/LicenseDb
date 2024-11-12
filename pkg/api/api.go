// SPDX-FileCopyrightText: 2023 Kavya Shukla <kavyuushukla@gmail.com>
// SPDX-FileCopyrightText: 2023 Siemens AG
// SPDX-FileContributor: Gaurav Mishra <mishra.gaurav@siemens.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/exp/maps"

	"github.com/fossology/LicenseDb/cmd/laas/docs"
	"github.com/fossology/LicenseDb/pkg/auth"
	"github.com/fossology/LicenseDb/pkg/db"
	"github.com/fossology/LicenseDb/pkg/middleware"
	"github.com/fossology/LicenseDb/pkg/models"
)

// Router Get the gin router with all the routes defined
//
//	@title						laas (License as a Service) API
//	@version					0.0.9
//	@description				Service to host license information for other services to query over REST API.
//
//	@contact.name				FOSSology
//	@contact.url				https://fossology.org
//	@contact.email				fossology@fossology.org
//
//	@license.name				GPL-2.0-only
//	@license.url				https://github.com/fossology/LicenseDb/blob/main/LICENSE
//
//	@BasePath					/api/v1
//
//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						Authorization
//	@description				Token from /login endpoint

const (
	DEFAULT_PORT                            = "8080"
	DEFAULT_READ_API_AUTHENTICATION_ENABLED = false
)

func Router() *gin.Engine {

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = DEFAULT_PORT
	}
	docs.SwaggerInfo.Host = fmt.Sprintf("localhost:%s", port)

	// workaround to add optional authentication: https://github.com/swaggo/swag/issues/1226
	oldSecurityScheme := regexp.MustCompile(`({\s*"ApiKeyAuth":\s*\[\]),\s*"{}":\s*\[\](\s*})`)
	docs.SwaggerInfo.SwaggerTemplate = oldSecurityScheme.ReplaceAllString(docs.SwaggerInfo.SwaggerTemplate, "$1$2, {}")

	// Convert the environment variable to a boolean
	authEnabled, err := strconv.ParseBool(os.Getenv("READ_API_AUTHENTICATION_ENABLED"))
	if err != nil {
		authEnabled = DEFAULT_READ_API_AUTHENTICATION_ENABLED
	}

	// r is a default instance of gin engine
	r := gin.Default()

	store := memstore.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("oidcSession", store))

	// return error for invalid routes
	r.NoRoute(HandleInvalidUrl)

	// CORS middleware
	r.Use(middleware.CORSMiddleware())

	// Pagination middleware
	r.Use(middleware.PaginationMiddleware())

	if authEnabled {
		unAuthorizedv1 := r.Group("/api/v1")
		{
			health := unAuthorizedv1.Group("/health")
			{
				health.GET("", GetHealth)
			}
			login := unAuthorizedv1.Group("/login")
			{
				login.POST("", auth.Login)
			}
			oidc := unAuthorizedv1.Group("/oidc")
			{
				oidc.GET("/login", auth.OidcLogin)
				oidc.GET("/callback", auth.OidcCallback)
			}
			apiCollection := unAuthorizedv1.Group("/apiCollection")
			{
				apiCollection.GET("", GetAPICollection)
			}
		}

		authorizedv1 := r.Group("/api/v1")
		authorizedv1.Use(middleware.AuthenticationMiddleware())
		{
			licenses := authorizedv1.Group("/licenses")
			{
				licenses.GET("", FilterLicense)
				licenses.GET(":shortname", GetLicense)
				licenses.GET("export", ExportLicenses)
				licenses.GET("/preview", GetAllLicensePreviews)
				licenses.POST("", CreateLicense)
				licenses.PATCH(":shortname", UpdateLicense)
				licenses.POST("import", ImportLicenses)
			}
			search := authorizedv1.Group("/search")
			{
				search.POST("", SearchInLicense)
			}
			users := authorizedv1.Group("/users")
			{
				users.GET("", auth.GetAllUser)
				users.GET(":id", auth.GetUser)
				users.POST("", auth.CreateUser)
			}
			obligations := authorizedv1.Group("/obligations")
			{
				obligations.GET("", GetAllObligation)
				obligations.GET("/preview", GetAllObligationPreviews)
				obligations.GET(":topic", GetObligation)
				obligations.GET(":topic/audits", GetObligationAudits)
				obligations.GET("export", ExportObligations)
				obligations.POST("", CreateObligation)
				obligations.POST("import", ImportObligations)
				obligations.PATCH(":topic", UpdateObligation)
				obligations.DELETE(":topic", DeleteObligation)
			}
			obMap := authorizedv1.Group("/obligation_maps")
			{
				obMap.GET("topic/:topic", GetObligationMapByTopic)
				obMap.GET("license/:license", GetObligationMapByLicense)
				obMap.PATCH("topic/:topic/license", PatchObligationMap)
				obMap.PUT("topic/:topic/license", UpdateLicenseInObligationMap)
			}
			audit := authorizedv1.Group("/audits")
			{
				audit.GET("", GetAllAudit)
				audit.GET(":audit_id", GetAudit)
				audit.GET(":audit_id/changes", GetChangeLogs)
				audit.GET(":audit_id/changes/:id", GetChangeLogbyId)
			}
		}
	} else {
		unAuthorizedv1 := r.Group("/api/v1")
		{
			licenses := unAuthorizedv1.Group("/licenses")
			{
				licenses.GET("", FilterLicense)
				licenses.GET(":shortname", GetLicense)
				licenses.GET("export", ExportLicenses)
				licenses.GET("/preview", GetAllLicensePreviews)
			}
			search := unAuthorizedv1.Group("/search")
			{
				search.POST("", SearchInLicense)
			}
			obligations := unAuthorizedv1.Group("/obligations")
			{
				obligations.GET("", GetAllObligation)
				obligations.GET("/preview", GetAllObligationPreviews)
				obligations.GET(":topic", GetObligation)
				obligations.GET(":topic/audits", GetObligationAudits)
				obligations.GET("export", ExportObligations)
			}
			obMap := unAuthorizedv1.Group("/obligation_maps")
			{
				obMap.GET("topic/:topic", GetObligationMapByTopic)
				obMap.GET("license/:license", GetObligationMapByLicense)
			}
			audit := unAuthorizedv1.Group("/audits")
			{
				audit.GET("", GetAllAudit)
				audit.GET(":audit_id", GetAudit)
				audit.GET(":audit_id/changes", GetChangeLogs)
				audit.GET(":audit_id/changes/:id", GetChangeLogbyId)
			}
			health := unAuthorizedv1.Group("/health")
			{
				health.GET("", GetHealth)
			}
			login := unAuthorizedv1.Group("/login")
			{
				login.POST("", auth.Login)
			}
			oidc := unAuthorizedv1.Group("/oidc")
			{
				oidc.GET("/login", auth.OidcLogin)
				oidc.GET("/callback", auth.OidcCallback)
			}
			apiCollection := unAuthorizedv1.Group("/apiCollection")
			{
				apiCollection.GET("", GetAPICollection)
			}
		}

		authorizedv1 := r.Group("/api/v1")
		authorizedv1.Use(middleware.AuthenticationMiddleware())
		{
			licenses := authorizedv1.Group("/licenses")
			{
				licenses.POST("", CreateLicense)
				licenses.PATCH(":shortname", UpdateLicense)
				licenses.POST("import", ImportLicenses)
			}
			users := authorizedv1.Group("/users")
			{
				users.GET("", auth.GetAllUser)
				users.GET(":id", auth.GetUser)
				users.POST("", auth.CreateUser)
			}
			obligations := authorizedv1.Group("/obligations")
			{
				obligations.POST("", CreateObligation)
				obligations.POST("import", ImportObligations)
				obligations.PATCH(":topic", UpdateObligation)
				obligations.DELETE(":topic", DeleteObligation)
			}
			obMap := authorizedv1.Group("/obligation_maps")
			{
				obMap.PATCH("topic/:topic/license", PatchObligationMap)
				obMap.PUT("topic/:topic/license", UpdateLicenseInObligationMap)
			}
		}
	}

	// Host the swagger UI at /swagger/index.html
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return r
}

// The HandleInvalidUrl function returns the error when an invalid url is entered
func HandleInvalidUrl(c *gin.Context) {

	er := models.LicenseError{
		Status:    http.StatusNotFound,
		Message:   "No such path exists please check URL",
		Error:     "invalid path",
		Path:      c.Request.URL.Path,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	c.JSON(http.StatusNotFound, er)
}

// The GetHealth function returns if the DB is running and connected.
//
//	@Summary		Check health
//	@Description	Check health of the service
//	@Id				getHealth
//	@Tags			Health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	models.LicenseError	"Heath is OK"
//	@Failure		500	{object}	models.LicenseError	"Connection to DB failed"
//	@Router			/health [get]
func GetHealth(c *gin.Context) {
	// Fetch one license from DB to check if connection is still working.
	var license models.LicenseDB
	err := db.DB.Where(&models.LicenseDB{}).First(&license).Error
	if license.Id == 0 || err != nil {
		errorMessage := ""
		if err != nil {
			errorMessage = err.Error()
		}
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Database is not running or connected",
			Error:     errorMessage,
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}
	er := models.LicenseError{
		Status:    http.StatusOK,
		Message:   "Database is running and connected",
		Error:     "",
		Path:      c.Request.URL.Path,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	c.JSON(http.StatusOK, er)
}

// The GetAPICollection function returns the apis which require authentication and which do not
//
//	@Summary		Returns the apis which require authentication and which do not
//	@Description	Returns the apis which require authentication and which do not
//	@Id				getAPICollection
//	@Tags			API Collection
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	models.APICollectionResponse
//	@Failure		500	{object}	models.LicenseError	"Unable to parse swagger docs"
//	@Router			/apiCollection [get]
func GetAPICollection(c *gin.Context) {
	var swaggerDocAPISecurityScheme models.SwaggerDocAPISecurityScheme

	if err := json.Unmarshal([]byte(docs.SwaggerInfo.ReadDoc()), &swaggerDocAPISecurityScheme); err != nil {
		er := models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "Unable to parse swagger docs",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		c.JSON(http.StatusInternalServerError, er)
		return
	}

	authEnabled, err := strconv.ParseBool(os.Getenv("READ_API_AUTHENTICATION_ENABLED"))
	if err != nil {
		authEnabled = DEFAULT_READ_API_AUTHENTICATION_ENABLED
	}

	var unAuthenticatedApis models.LinksCollection
	var authenticatedApis models.LinksCollection
	unAuthenticatedApis.Links = make(map[string]models.Api)
	authenticatedApis.Links = make(map[string]models.Api)

	for _, path := range maps.Keys(swaggerDocAPISecurityScheme.Paths) {
		for _, method := range maps.Keys(swaggerDocAPISecurityScheme.Paths[path]) {
			if len(swaggerDocAPISecurityScheme.Paths[path][method].Security) == 0 ||
				(len(swaggerDocAPISecurityScheme.Paths[path][method].Security) == 2 && !authEnabled) {
				unAuthenticatedApis.Links[swaggerDocAPISecurityScheme.Paths[path][method].OperationId] = models.Api{
					Href:          fmt.Sprintf("%s%s", swaggerDocAPISecurityScheme.BasePath, path),
					RequestMethod: method,
				}
			} else {
				authenticatedApis.Links[swaggerDocAPISecurityScheme.Paths[path][method].OperationId] = models.Api{
					Href:          fmt.Sprintf("%s%s", swaggerDocAPISecurityScheme.BasePath, path),
					RequestMethod: method,
				}
			}
		}
	}

	apiCollectionResponse := &models.APICollectionResponse{
		Status: http.StatusOK,
		Data: models.APICollection{
			Authenticated:   authenticatedApis,
			UnAuthenticated: unAuthenticatedApis,
		},
	}

	c.JSON(http.StatusOK, apiCollectionResponse)
}
