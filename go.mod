module github.com/stevesloka/envoy-xds-server

go 1.18

replace github.com/envoyproxy/go-control-plane => github.com/voyagermesh/go-control-plane v0.11.2-0.20240624113032-e1d169cef757

require (
	github.com/envoyproxy/go-control-plane v0.12.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/golang/protobuf v1.5.3
	github.com/sirupsen/logrus v1.7.0
	google.golang.org/grpc v1.58.3
	google.golang.org/protobuf v1.32.0
	gopkg.in/yaml.v2 v2.2.3

)

require (
	github.com/census-instrumentation/opencensus-proto v0.4.1 // indirect
	github.com/cncf/xds/go v0.0.0-20230607035331-e9ce68804cb4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.0.2 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20230711160842-782d3b101e98 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230711160842-782d3b101e98 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
)
