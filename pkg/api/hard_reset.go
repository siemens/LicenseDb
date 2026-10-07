// SPDX-FileContributor: Dearsh Oberoi <dearsh.oberoi@siemens.com>
//
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"net/http"
	"time"

	"github.com/fossology/LicenseDb/pkg/db"
	"github.com/fossology/LicenseDb/pkg/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HardResetDatabase marks licenses and obligations inactive.
//
//	@Summary		Hard reset database
//	@Description	Mark all licenses and obligations inactive
//	@Id				HardResetDatabase
//	@Tags			Admin
//	@Produce		json
//	@Success		204
//	@Failure		500	{object}	models.LicenseError	"failed to hard reset database"
//	@Security		ApiKeyAuth
//	@Router			/hard-reset [delete]
func HardResetDatabase(c *gin.Context) {
	activeStatus := true
	inactiveStatus := false
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.LicenseDB{}).Where(&models.LicenseDB{Active: &activeStatus}).Updates(&models.LicenseDB{Active: &inactiveStatus}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.Obligation{}).Where(&models.Obligation{Active: &activeStatus}).Updates(&models.Obligation{Active: &inactiveStatus}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, models.LicenseError{
			Status:    http.StatusInternalServerError,
			Message:   "failed to hard reset database",
			Error:     err.Error(),
			Path:      c.Request.URL.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		})
		return
	}

	c.Status(http.StatusNoContent)
}
