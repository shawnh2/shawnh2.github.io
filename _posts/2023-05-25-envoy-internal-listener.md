---
title: Envoy 中的 Internal Listener 机制
layout: article
---

Envoy 支持用户态的 socket，而且在 Enovy 中，用于接受用户态连接的 listener 被称为 internal listener。internal listener 一般用于接受来自 Envoy 内部的连接，例如从 upstream cluster 接受连接请求并建立 TCP 流。使用 internal listener 时，必须将它的 name 作为一个 upstream cluster 的 endpoint 地址。

![envoy-il-base](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-25/envoy-il-base.png)

<!--more-->

而且在 Envoy 的配置中，也需在`bootstrap_extensions`中指定使用 internal listener：
```yaml
bootstrap_extensions:
- name: envoy.bootstrap.internal_listener
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
```
为了避免在同一个 upstream cluster 中有多个 endpoints 引用了同一个 internal listener，可设置`clusters[i].load_assignment.endpoints[j].lb_endpoints[k].endpoint.address.endpoint_id`字段来增强辨识度。该字段与 internal listener name 的组合可唯一确定一个 endpoint。

## Chaining proxies
[Envoy 有个示例](https://github.com/envoyproxy/envoy/blob/c2ae2211196a48b12d2e36d00c6c2889ae2f434a/configs/internal_listener_proxy.yaml)，可以将内部的两个 TCP 代理通过 internal listener，实现把连接转发到不同的端口上。如下图所示，在 9999 端口的 TCP 连接被转发到了 10000 端口上。

![envoy-il-chain-proxy](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-25/envoy-il-chain-proxy.png)
## Encapsulate HTTP GET in CONNECT
Envoy 引入 internal listener 的一个原因就是：HCM 不能在 upstream 的 HTTP CONNECT 请求中代理  HTTP GET 请求，即不支持直接将 downstream 的 HTTP 请求通过 HTTP CONNECT 转发给 upstream。故需要 internal listener 这样一个中间角色来做中转。

Envoy 同样也提供了[一个示例](https://github.com/envoyproxy/envoy/blob/c2ae2211196a48b12d2e36d00c6c2889ae2f434a/configs/encapsulate_http_in_http2_connect.yaml)。如下图所示，对于所有来自 10000 端口的 HTTP 请求，将其封装至一个 HTTP CONNECT 请求之中，发送到上游 10001 端口。internal listener 中配置了 TcpProxy 的`tunneling_config`，表示 TcpProxy 将同 upstream 建立一个 HTTP 隧道，而隧道采用的具体协议由 upstream cluster 指定。

![envoy-il-encap](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-25/envoy-il-encap.png)

> 上图将 Endpoint 画到了 Enovy 的外面，是用于指示这个 Endpoint 是一个真实的、可以提供服务的 Endpoint；而前面那些图中的 Endpoint 画在了 Enovy 内部，只是用于指示它是 cluster 的一个字段而已。

这种使用 internal listener 来建立 CONNECT 隧道的方式，相当于是将 internal listener 作为了隧道的客户端。
## Decapsulate HTTP CONNECT
与上述的示例相呼应，对于一个 GET-in-CONNECT 请求，若要解析 CONNECT 中的 GET，也需要两个 HCM，一个用于从 CONNECT 请求中提取 TCP 流并将其重定向到另一个 HCM，另一个 HCM 负责解析 GET 请求。Enovy 同样提供了[示例配置](https://github.com/envoyproxy/envoy/blob/5b270c2f2a14ea4eac609bf855edcb8c051c2a39/configs/terminate_http_in_http2_connect.yaml)，如下图所示。

其中，第一个 HCM 需要配置`upgrade_type: CONNECT`，表示支持 CONNECT 隧道，并配置`http2_protocol_options`表示使用 HTTP/2 协议。internal listener 从隧道中获取 TCP 流解析出 HTTP GET 请求，并直接返回一个 HTTP 200 响应。可见此时，internal listener 作为了隧道的服务端。

![envoy-il-decap](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-25/envoy-il-decap.png)

如果结合 Envoy Encapsulate 和 Decapsulate 两种部署方式，采用两个 Envoy 来作为 HTTP CONNECT 隧道的两端，即可以得到一个端到端的 HTTP CONNECT 隧道。
## Reference

1. [https://www.envoyproxy.io/docs/envoy/latest/configuration/other_features/internal_listener](https://www.envoyproxy.io/docs/envoy/latest/configuration/other_features/internal_listener)
2. [https://www.zhaohuabing.com/post/2022-09-11-ambient-deep-dive-1/](https://www.zhaohuabing.com/post/2022-09-11-ambient-deep-dive-1/)
