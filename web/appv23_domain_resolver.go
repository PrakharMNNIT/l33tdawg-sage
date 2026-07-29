package web

// resolveEffectiveOwningAncestor preserves the legacy ownership walk before
// app-v23, while making every consensus-marked shared namespace a hard
// inheritance barrier after activation. Dashboard preflights must use the same
// resolver as consensus or they can advertise/sign with a broader ancestor
// owner for a descendant that app-v23 deliberately treats as ownerless.
func (h *DashboardHandler) resolveEffectiveOwningAncestor(
	domain string,
) (owner, ownedDomain string, err error) {
	if h.appV23IsActive() {
		return h.BadgerStore.ResolveAppV23OwningAncestor(domain)
	}
	return h.BadgerStore.ResolveOwningAncestor(domain)
}
