package handler

import (
	"net/http"

	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

// Coverage 返回项目覆盖率与未覆盖队列（只读，project:read 权限）。
func (h *ProjectHandler) Coverage(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	coverage, err := h.db.ProjectCoverage(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_coverage_failed", "读取项目覆盖率失败")
		return
	}
	c.JSON(http.StatusOK, coverage)
}
