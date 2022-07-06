package dto

// swagger:model BaseResponse
type BaseResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

func NewBaseResponse(Code int, Data interface{}) *BaseResponse {
	return &BaseResponse{
		Code: Code,
		Data: Data,
	}
}
