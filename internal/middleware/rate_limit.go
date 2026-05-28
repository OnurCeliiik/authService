package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type visitorWindow struct {
	count       int
	windowStart time.Time
}

func RateLimitByIP(limit int, window time.Duration) gin.HandlerFunc {
	var (
		mu       sync.Mutex
		visitors = make(map[string]visitorWindow)
	)

	return func(c *gin.Context) {
		now := time.Now()
		ip := c.ClientIP()

		mu.Lock()
		v := visitors[ip]
		if v.windowStart.IsZero() || now.Sub(v.windowStart) >= window {
			v = visitorWindow{
				count:       0,
				windowStart: now,
			}
		}
		v.count++
		visitors[ip] = v
		mu.Unlock()

		if v.count > limit {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
