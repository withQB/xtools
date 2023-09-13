package xtools

import (
	"unsafe"

	"github.com/withqb/xtools/spec"
)

// EDU represents a EDU received via federation
type EDU struct {
	Type        string       `json:"edu_type"`
	Origin      string       `json:"origin"`
	Destination string       `json:"destination,omitempty"`
	Content     spec.RawJSON `json:"content,omitempty"`
}

func (e *EDU) CacheCost() int {
	return int(unsafe.Sizeof(*e)) +
		len(e.Type) +
		len(e.Origin) +
		len(e.Destination) +
		cap(e.Content)
}
