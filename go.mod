module github.com/withqb/xtools

go 1.21

replace (
github.com/withqb/xcore => ../xcore
github.com/withqb/xutil => ../xutil
)

require (
	github.com/sirupsen/logrus v1.9.3
	github.com/tidwall/gjson v1.16.0
	github.com/tidwall/sjson v1.2.5
	github.com/withqb/xcore v0.0.1
	github.com/withqb/xutil v0.0.1
	golang.org/x/crypto v0.13.0
	gopkg.in/macaroon.v2 v2.1.0
)

require (
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
)
