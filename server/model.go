package server

type LicenseSignRequest struct {
	LicenseEnv      string `json:"license_env" form:"license_env" `
	LicenseTag      string `json:"license_tag" form:"license_tag" `
	LicenseDeadline int    `json:"license_deadline" form:"license_deadline" `
}

type Response struct {
	// Code defines the business error code.
	Code string `json:"code"`

	// Message contains the detail of this message.
	// This message is suitable to be exposed to external
	Message string `json:"message"`

	//RequestId
	RequestId string `json:"requestId"`

	// Data returns the business data.
	Data interface{} `json:"data"`
}
