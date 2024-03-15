package server

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/semaphore"
	"k8s.io/klog/v2"
)

var sem = semaphore.NewWeighted(10)

func LicenseSign(c *gin.Context) {
	var req LicenseSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		klog.Errorf("parameter is not valid: %v", err)
		c.JSON(http.StatusBadRequest, Response{
			Code:      "InvalidParameter",
			Message:   "parameter is not valid",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	klog.Infof("Type of req.LicenseEnv: %v", reflect.TypeOf(req.LicenseEnv))
	klog.Infof("Type of req.LicenseTag: %v", reflect.TypeOf(req.LicenseTag))
	klog.Infof("Type of req.LicenseDeadline: %v", reflect.TypeOf(req.LicenseDeadline))

	if req.LicenseEnv == "" {
		klog.Errorf("licenseEnv is not valid: %v", req.LicenseEnv)
		c.JSON(http.StatusBadRequest, Response{
			Code:      "InvalidParameter",
			Message:   "licenseEnv is not valid",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	if req.LicenseTag == "" {
		klog.Errorf("licenseTag is not valid: %v", req.LicenseTag)
		c.JSON(http.StatusBadRequest, Response{
			Code:      "InvalidParameter",
			Message:   "licenseTag is not valid",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	if req.LicenseDeadline == 0 {
		klog.Errorf("licenseDeadline is not valid: %v", req.LicenseDeadline)
		c.JSON(http.StatusBadRequest, Response{
			Code:      "InvalidParameter",
			Message:   "licenseDeadline is not valid",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	// Wait for a token from the semaphore
	if err := sem.Acquire(context.Background(), 1); err != nil {
		klog.Errorf("Failed to acquire semaphore: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:      "InternalError",
			Message:   "Failed to start program",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	// Run external program

	cmd := exec.Command("/usr/src/signTools/license_sign", req.LicenseEnv, req.LicenseTag, strconv.Itoa(req.LicenseDeadline))
	sem.Release(1)
	//打印命令
	klog.Infof("Running command with arguments: %v, %v, %v", req.LicenseEnv, req.LicenseTag, strconv.Itoa(req.LicenseDeadline))
	output, err := cmd.Output()
	if err != nil {
		klog.Errorf("Failed to run program: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:      "InternalError",
			Message:   "Failed to start program",
			RequestId: "",
			Data:      nil,
		})
		return
	}

	fmt.Println(string(output))
	c.JSON(http.StatusOK, Response{
		Code:      "Success",
		Message:   "Success to sign license",
		RequestId: "",
		Data:      string(output),
	})

}
