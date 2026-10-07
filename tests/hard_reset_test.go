// SPDX-FileContributor: Dearsh Oberoi <dearsh.oberoi@siemens.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fossology/LicenseDb/pkg/db"
	"github.com/fossology/LicenseDb/pkg/models"
	"github.com/fossology/LicenseDb/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestHardResetDatabase(t *testing.T) {
	defer utils.Populatedb(testDataFile)

	loginAs(t, "admin")
	clientID := fmt.Sprintf("hard-reset-client-%d", time.Now().UnixNano())
	createOIDCPayload := models.CreateOidcClientDTO{ClientId: clientID}
	createW := makeRequest("POST", "/oidcClients", createOIDCPayload, true)
	assert.Equal(t, http.StatusCreated, createW.Code)

	var usersBeforeReset int64
	assert.NoError(t, db.DB.Model(&models.User{}).Count(&usersBeforeReset).Error)

	var oidcClientsBeforeReset int64
	assert.NoError(t, db.DB.Model(&models.OidcClient{}).Count(&oidcClientsBeforeReset).Error)

	unchangedTables := []string{
		"obligation_types",
		"obligation_classifications",
		"obligation_licenses",
		"obligation_categories",
		"audits",
		"change_logs",
	}
	tableCountsBeforeReset := make(map[string]int64, len(unchangedTables))
	for _, table := range unchangedTables {
		var count int64
		assert.NoError(t, db.DB.Table(table).Count(&count).Error)
		tableCountsBeforeReset[table] = count
	}

	loginAs(t, "admin")
	resetW := makeRequest("DELETE", "/hard-reset", nil, true)
	assert.Equal(t, http.StatusNoContent, resetW.Code)

	var usersAfterReset int64
	assert.NoError(t, db.DB.Model(&models.User{}).Count(&usersAfterReset).Error)
	assert.Equal(t, usersBeforeReset, usersAfterReset)

	var oidcClientsAfterReset int64
	assert.NoError(t, db.DB.Model(&models.OidcClient{}).Count(&oidcClientsAfterReset).Error)
	assert.Equal(t, oidcClientsBeforeReset, oidcClientsAfterReset)

	for _, table := range unchangedTables {
		var count int64
		assert.NoError(t, db.DB.Table(table).Count(&count).Error)
		assert.Equal(t, tableCountsBeforeReset[table], count, "expected %s rows to be preserved", table)
	}

	active := true
	var activeLicenses int64
	assert.NoError(t, db.DB.Model(&models.LicenseDB{}).Where(&models.LicenseDB{Active: &active}).Count(&activeLicenses).Error)
	assert.Zero(t, activeLicenses)

	var activeObligations int64
	assert.NoError(t, db.DB.Model(&models.Obligation{}).Where(&models.Obligation{Active: &active}).Count(&activeObligations).Error)
	assert.Zero(t, activeObligations)
}

func TestHardResetDatabaseUnauthorized(t *testing.T) {
	w := makeRequest("DELETE", "/hard-reset", nil, false)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
