// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package resources

import (
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"github.com/golang/protobuf/ptypes/duration"
	"google.golang.org/protobuf/types/known/anypb"
	"time"

	"github.com/golang/protobuf/ptypes"

	postgres "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/network/postgres_proxy/v3alpha"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

const (
	UpstreamHost = "www.envoyproxy.io"
	UpstreamPort = 80
)

func MakeCluster(clusterName string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       ptypes.DurationProto(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		//LoadAssignment:       makeEndpoint(clusterName, UpstreamHost),
		DnsLookupFamily:  cluster.Cluster_V4_ONLY,
		EdsClusterConfig: makeEDSCluster(),
	}
}

func makeEDSCluster() *cluster.Cluster_EdsClusterConfig {
	return &cluster.Cluster_EdsClusterConfig{
		EdsConfig: makeConfigSource(),
	}
}

func MakeEndpoint(clusterName string, eps []Endpoint) *endpoint.ClusterLoadAssignment {
	var endpoints []*endpoint.LbEndpoint

	for _, e := range eps {
		endpoints = append(endpoints, &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol: core.SocketAddress_TCP,
								Address:  e.UpstreamHost,
								PortSpecifier: &core.SocketAddress_PortValue{
									PortValue: e.UpstreamPort,
								},
							},
						},
					},
				},
			},
		})
	}

	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: endpoints,
		}},
	}
}

func MakeRoute(routes []Route) *route.RouteConfiguration {
	var rts []*route.Route

	for _, r := range routes {
		rts = append(rts, &route.Route{
			//Name: r.Name,
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: r.Prefix,
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: r.Cluster,
					},
				},
			},
		})
	}

	return &route.RouteConfiguration{
		Name: "listener_0",
		VirtualHosts: []*route.VirtualHost{{
			Name:    "local_service",
			Domains: []string{"*"},
			Routes:  rts,
		}},
	}
}

func MakePostgresListener(lisName, dbBackend, otelBackend, address string, port uint32) *listener.Listener {

	mgrTCP := &tcp.TcpProxy{
		StatPrefix: "tcp",
		ClusterSpecifier: &tcp.TcpProxy_Cluster{
			Cluster: dbBackend,
		},
	}
	mgrtcpAny, err := anypb.New(mgrTCP)
	if err != nil {
		return nil
	}

	otl := &tracev3.OpenTelemetryConfig{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
					ClusterName: otelBackend,
				},
			},
			Timeout: &duration.Duration{
				Seconds: 1,
				Nanos:   0,
			},
			InitialMetadata: nil,
		},
		ServiceName: "otel-dep",
	}

	otelAny, err := anypb.New(otl)

	mgrPostgres := &postgres.PostgresProxy{
		StatPrefix:       "lulu",
		EnableSqlParsing: nil,
		TerminateSsl:     false,
		UpstreamSsl:      postgres.PostgresProxy_DISABLE,
		AuditLog: &tracev3.Tracing_Http{
			Name: "envoy.tracers.opentelemetry",
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: otelAny,
			},
		},
	}

	mgrPostgresAny, err := anypb.New(mgrPostgres)

	return &listener.Listener{
		Name: lisName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						//Name: wellknown.HTTPConnectionManager,
						Name: "envoy.filters.network.postgres_proxy",
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: mgrPostgresAny,
						},
					},
					{
						Name: "envoy.filters.network.tcp_proxy",
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: mgrtcpAny,
						},
					},
				},
			},
		},
	}
}

//
//func MakePostgresListener(listenerName, route, address string, port uint32) *listener.Listener {
//	//routerConfig, _ := anypb.New(&router.Router{})
//	// postgres configuration
//	manager := &postgres.PostgresProxy{
//		StatPrefix:       "lulu_pg",
//		EnableSqlParsing: nil,
//		TerminateSsl:     false,
//		UpstreamSsl:      0,
//	}
//	// TCP configuration
//	manager2 := &tcp.TcpProxy{
//		StatPrefix: "lulu_tcp",
//		ClusterSpecifier: &tcp.TcpProxy_Cluster{
//			Cluster: "pg_cluster",
//		},
//	}
//
//	//// HTTP filter configuration
//	//manager := &hcm.HttpConnectionManager{
//	//	CodecType:  hcm.HttpConnectionManager_AUTO,
//	//	StatPrefix: "http",
//	//	RouteSpecifier: &hcm.HttpConnectionManager_Rds{
//	//		Rds: &hcm.Rds{
//	//			ConfigSource:    makeConfigSource(),
//	//			RouteConfigName: "listener_0",
//	//		},
//	//	},
//	//	HttpFilters: []*hcm.HttpFilter{{
//	//		Name:       wellknown.Router,
//	//		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
//	//	}},
//	//}
//	pbst, err := ptypes.MarshalAny(manager)
//	//pbst2, err := ptypes.MarshalAny(manager2)
//	pbst2, err := anypb.New(manager2)
//	if err != nil {
//		panic(err)
//	}
//	if err != nil {
//		panic(err)
//	}
//
//	return &listener.Listener{
//		Name: listenerName,
//		Address: &core.Address{
//			Address: &core.Address_SocketAddress{
//				SocketAddress: &core.SocketAddress{
//					Protocol: core.SocketAddress_TCP,
//					Address:  address,
//					PortSpecifier: &core.SocketAddress_PortValue{
//						PortValue: port,
//					},
//				},
//			},
//		},
//		FilterChains: []*listener.FilterChain{{
//			Filters: []*listener.Filter{{
//				//Name: wellknown.HTTPConnectionManager,
//				Name: "envoy.filters.network.postgres_proxy",
//				ConfigType: &listener.Filter_TypedConfig{
//					TypedConfig: pbst,
//				},
//			},
//				{
//					Name: "envoy.filters.network.tcp_proxy",
//					ConfigType: &listener.Filter_TypedConfig{
//						TypedConfig: pbst2,
//					},
//				},
//			},
//		}},
//	}
//}

func MakeHTTPListener(listenerName, route, address string, port uint32) *listener.Listener {
	//routerConfig, _ := anypb.New(&router.Router{})
	// postgres configuration
	manager := &postgres.PostgresProxy{
		StatPrefix:       "lulu_pg",
		EnableSqlParsing: nil,
		TerminateSsl:     false,
		UpstreamSsl:      0,
	}
	// TCP configuration
	manager2 := &tcp.TcpProxy{
		StatPrefix: "lulu_tcp",
		ClusterSpecifier: &tcp.TcpProxy_Cluster{
			Cluster: "pg_cluster",
		},
	}

	//// HTTP filter configuration
	//manager := &hcm.HttpConnectionManager{
	//	CodecType:  hcm.HttpConnectionManager_AUTO,
	//	StatPrefix: "http",
	//	RouteSpecifier: &hcm.HttpConnectionManager_Rds{
	//		Rds: &hcm.Rds{
	//			ConfigSource:    makeConfigSource(),
	//			RouteConfigName: "listener_0",
	//		},
	//	},
	//	HttpFilters: []*hcm.HttpFilter{{
	//		Name:       wellknown.Router,
	//		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
	//	}},
	//}
	pbst, err := ptypes.MarshalAny(manager)
	//pbst2, err := ptypes.MarshalAny(manager2)
	pbst2, err := anypb.New(manager2)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				//Name: wellknown.HTTPConnectionManager,
				Name: "envoy.filters.network.postgres_proxy",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			},
				{
					Name: "envoy.filters.network.tcp_proxy",
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: pbst2,
					},
				},
			},
		}},
	}
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}
