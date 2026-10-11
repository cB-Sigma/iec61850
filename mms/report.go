package mms

// Additive export used by the ICCP / TASE.2 client: an unconfirmed
// InformationReport sent by the calling side (IEC 60870-6-503 uses one
// to acknowledge critical transfer reports).

// SendInformationReport sends an unconfirmed InformationReport on the
// association.
func (c *Client) SendInformationReport(spec VariableSpec, results []AccessResult) error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.t.sendMMS(ctxMMS, InformationReportPDU(spec, results)); err != nil {
		c.fail(err)
		return err
	}
	return nil
}
