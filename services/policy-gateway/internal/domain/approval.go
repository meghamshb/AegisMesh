package domain

type ApproveRequestBody struct {
	Remember bool       `json:"remember"`
	Scope    RuleScope  `json:"scope"`
}

type DenyRequestBody struct {
	Feedback string `json:"feedback"`
}

type ErrRememberScopeNotSupported struct {
	Scope RuleScope
}

func (e ErrRememberScopeNotSupported) Error() string {
	return "remember=true only supports scope=org in phase 3 (got " + string(e.Scope) + ")"
}

type ErrRememberCONNECTNotAllowed struct {
	Host string
}

func (e ErrRememberCONNECTNotAllowed) Error() string {
	return "remember=true is not allowed for CONNECT tunnels (host=" + e.Host + "); use approve-once instead"
}

type ErrRememberRequiresAuth struct{}

func (e ErrRememberRequiresAuth) Error() string {
	return "remember=true requires GATEWAY_ADMIN_TOKEN to be configured"
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
