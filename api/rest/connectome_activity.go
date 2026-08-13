package rest

// connectomeActivityEvent is the SSE event name announcing that the local agent
// connectome may have changed.
//
// It is spelled here rather than imported from web because api/rest does not
// depend on web; the name is held to web.EventConnectome and to the dashboard's
// subscription list by TestConnectomeActivityEventNameMatchesRegistry.
const connectomeActivityEvent = "connectome"
