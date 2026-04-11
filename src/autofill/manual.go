package autofill

func CaptureCurrentRequestContext() (RequestContext, error) {
	ctx, err := captureActiveWindowContext()
	if err != nil {
		return RequestContext{}, err
	}
	return requestContextFromWindow(ctx), nil
}

func TypeFillResponse(resp FillResponse) error {
	engine := newSystemEngine()
	sequence := resp.Sequence
	if sequence == "" {
		sequence = DefaultSequenceTemplate
	}
	return engine.Type(renderSequence(sequence, resp.Username, resp.Password, resp.TOTP))
}

func TypeMailOTP(code string) error {
	engine := newSystemEngine()
	return engine.Type(renderSequence("{TOTP}", "", "", code))
}
