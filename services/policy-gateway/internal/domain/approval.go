package domain

type ApproveRequestBody struct {
	Remember bool       `json:"remember"`
	Scope    RuleScope  `json:"scope"`
}

type DenyRequestBody struct {
	Feedback string `json:"feedback"`
}

type ErrRequestNotPending struct {
	ID     string
	Status RequestStatus
}

func (e ErrRequestNotPending) Error() string {
	return "request " + e.ID + " is not pending (status=" + string(e.Status) + ")"
}

type ErrNotFound struct {
	Resource string
	ID       string
}

func (e ErrNotFound) Error() string {
	return e.Resource + " not found: " + e.ID
}
