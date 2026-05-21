package health

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const dbPingTimeout = 2 * time.Second

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) Health(c *gin.Context) {
	status := http.StatusOK
	body := gin.H{"status": "ok"}

	if h.db != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), dbPingTimeout)
		defer cancel()

		if err := h.db.WithContext(ctx).Exec("SELECT 1").Error; err != nil {
			status = http.StatusServiceUnavailable
			body["status"] = "degraded"
			body["database"] = "unavailable"
		} else {
			body["database"] = "ok"
		}
	}

	c.JSON(status, body)
}
