package tracee.BYPASS

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-BYPASS",
    "version": "0.1.0",
    "name": "Bypass - True Filter",
    "description": "Match any event",
    "tags": ["linux", "container"],
    "properties": {}
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "*"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
    true
}
