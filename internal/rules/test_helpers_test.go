package rules

type documentTestRule struct {
	meta     Metadata
	findings []Finding
}

func (r documentTestRule) Metadata() Metadata {
	return r.meta
}

func (r documentTestRule) CheckDocument(_ Context, _ DocumentView) []Finding {
	cloned := make([]Finding, len(r.findings))
	copy(cloned, r.findings)
	return cloned
}

type noPhaseTestRule struct {
	meta Metadata
}

func (r noPhaseTestRule) Metadata() Metadata {
	return r.meta
}
