---
title: "Merbridge: 基于 eBPF 加速 Istio 的流量转发能力"
layout: article
key: merbridge_dive_in
tags:
- Istio
- Network
- eBPF
---

> 本文代码基于 Merbridge [HEAD c16cc43](https://github.com/merbridge/merbridge/tree/c16cc436ca0a27570be2b42bb3caccced774e614) 展开。

## 简介

Merbridge 是基于 eBPF 实现的一套可用于服务网格中流量拦截与高性能转发的方案，其支持多种服务网格项目（Istio、Kuma、Linkerd 等）适配，本文只以 Istio Sidecar 模式为例展开。

具体来讲（以 Istio Sidecar 模式为例），下图为原始流量路径：

![istio-sidecar-traffic.png](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-06/istio-sidecar-traffic.png)

<!--more-->

在使用 Merbridge 后，可有效减少业务数据包与内核网络交互的次数，服务间的网络数据路径就只剩下代理之间的了。

![merbridge-traffic.png](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-06/merbridge-traffic.png)

甚至，若两个 Pod 位于同一个 Node 之上，它们之间的网络数据路径还能更加简洁。

![merbridge-traffic-same-node.png](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-06/merbridge-traffic-same-node.png)

## 组成

Merbridge 以 DaemonSet 方式运行在集群中，其运行启动时会：

- 首先加载（Load）所有 eBPF 程序
- 其次启动 Controller
- 最后关联（Attach）所有 eBPF 程序

### eBPF 程序清单

其中，无论是加载（Load）还是关联（Attach）eBPF 程序，Merbridge 都是以直接执行 `bpftool` 命令的方法进行的，所有的 eBPF 程序都会被挂载到 `/sys/fs/bpf` 路径下。

Merbridge 共操作以下几种 eBPF 程序：

| name | mount path | attach to | attach type | attach prog |
| ---- | ---- | ---- | ---- | ---- |
| connect | `/sys/fs/bpf/connect/connect` | cgroup2 | connect4/6 | `/sys/fs/bpf/connect/connect/cgroup_connect` 4/6 |
| sockops | `/sys/fs/bpf/connect/sockops` | cgroup2 | sock_ops | `/sys/fs/bpf/connect/sockops` |
| get_sockopts | `/sys/fs/bpf/connect/get_sockopts` | cgroup2 | getsockopt | `/sys/fs/bpf/connect/get_sockopts` |
| redir | `/sys/fs/bpf/connect/redir` | prog | msg_verdict | `/sys/fs/bpf/connect/redir` |
| bind | `/sys/fs/bpf/connect/bind` | cgroup2 | bind4 | `/sys/fs/bpf/connect/bind` |
| sendmsg | `/sys/fs/bpf/connect/sendmsg` | cgroup2 | sendmsg4/6 | `/sys/fs/bpf/connect/sendmsg/cgroup_sendmsg` 4/6 |
| recvmsg | `/sys/fs/bpf/connect/recvmsg` | cgroup2 | recvmsg4/6 | `/sys/fs/bpf/connect/recvmsg/cgroup_recvmsg` 4/6 |
| mb_process | `/sys/fs/bpf/connect/mb_process` | - | - | - |

除此之外，Merbridge 还创建了以下 bpf map：

| name | mount path | type | 注释 | used by |
| ---- | ---- | ---- | ---- | ---- |
| cookie_original_dst | `/sys/fs/bpf/connect/cookie_original_dst` | lru_hash | socket cookie address 与流量原始目的地址的 1:1 映射 | connect｜sockops｜sendmsg｜recvmsg |
| local_pod_ips | `/sys/fs/bpf/connect/local_pod_ips` | hash | pod IP 与 `podConfig` 的 1:1 映射 | connect |
| process_ip | `/sys/fs/bpf/connect/process_ip` | lru_hash | process id 与 pod IP 的 1:1 映射 | connect｜sockops |
| cgroup_info_map | `/sys/fs/bpf/connect/cgroup_info_map` | lru_hash | cgroup id 与 cgroup info 的 1:1 映射 | connect｜bind｜sendmsg｜recvmsg |
| mark_pod_ips_map | `/sys/fs/bpf/connect/mark_pod_ips_map` | hash |  | connect｜sendmsg｜recvmsg |
| settings | `/sys/fs/bpf/connect/settings` | hash |  | connect｜sockops｜bind |
| pair_original_dst | `/sys/fs/bpf/connect/pair_original_dst` | lru_hash | 四元组与原始目的地址的 1:1 映射 | sockops｜get_sockopts |
| sock_pair_map | `/sys/fs/bpf/connect/sock_pair_map` | sockhash | sock 与四元组的 1:1 映射 | sockops｜redir |
| process_events | `/sys/fs/bpf/connect/process_events` | perf_event_array |  | mb_process |

### Local IP Controller

Merbridge 启动的 Controller 名为 Local IP Controller，其本质上是一个包含了对 Pod 和 Namespace 资源监听的 Informer。

由于 Merbridge 以 DaemonSet 模式运行，故每个 Node 上的 Merbridge 只监听**当前节点中所有 Pod 的资源变化**。并在监听到 Istio 所管理的 Pod 资源变化时（具体来说就是被注入了 Sidecar）更新 `local_pod_ips` 这个 bpf map，其中 map 的 key 为 Pod IP，value 为 `podConfig` 结构体：

```go
type podConfig struct {  
	statusPort uint16  
	_ uint16 // pad  
	excludeOutRanges [MaxItemLen]cidr     ===>   type cidr struct {  
	includeOutRanges [MaxItemLen]cidr                net uint32 // network order  
	includeInPorts   [MaxItemLen]uint16              mask uint8  
	includeOutPorts  [MaxItemLen]uint16              _ [3]uint8 // pad  
	excludeInPorts   [MaxItemLen]uint16          }
	excludeOutPorts  [MaxItemLen]uint16  
}

const MaxItemLen = 20
```

这些结构体字段记录的信息同 [Istio Resource Annotations](https://istio.io/latest/docs/reference/config/annotations/#SidecarTrafficExcludeInboundPorts)。在 Controller 的实现中，它们都是通过解析 Pod 的 anntations 获取的。

## 工作方式

若无特别说明，本部分只关注 IPv4 协议的网络。

回忆在 Istio 中 Sidecar 拦截流量是通过 iptables 的手段，将应用向外部的流量被 iptables 的 OUTPUT 拦截，转发至 Sidecar 的 15001 端口；外部向应用的流量则是被 iptables 中的 PREROUTING 拦截，转发至 Sidecar 的 15006 端口。

Istio 使用 iptables 的 DNAT 功能做流量转发，Merbridge 则使用 eBPF 实现，为了能够达到 iptables DNAT 能力的效果，需要：

- 修改连接发起时的目的地址，让流量能够发送至新的端口
- 让 Envoy 能够识别流量原始的目的地址

### 出口流量处理

本节以 TCP 连接为例，介绍从应用容器（App）到 Sidecar Envoy 的 15001 端口连接建立的过程。

![merbridge-outbound.png](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-06/merbridge-outbound.png)

对于从应用容器的出口流量，需要将其重定向到 Sidecar Envoy 的 15001 端口（即 `127.0.0.1:15001`）。

1\. 在应用向外发起连接时，`connect` eBPF 程序会将目的地址修改为 `127.x.y.z:15001` ，并使用 `cookie_original_dst` map 保存流量原始的目的地址。不修改目的地址为 `127.0.0.1` 的原因是：**避免不同 Pod 中产生冲突的四元组信息**。

```c
static __u32 outip = 1;

static inline int tcp_connect4(struct bpf_sock_addr *ctx)
{
    // 通过从 cgroup_info_map 中获取的 cgroup_info 来判断是否为服务网格中 Pod 的流量
    // ...
    
    __u32 curr_pod_ip;
    __u32 _curr_pod_ip[4];
    set_ipv6(_curr_pod_ip, cg_info.cgroup_ip);
    curr_pod_ip = get_ipv4(_curr_pod_ip);
    
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 dst_ip = ctx->user_ip4;
    if (uid != SIDECAR_USER_ID) {  // 1337 是 Istio 为 sidecar 预留的 Application UIDs
        // 忽略目的地址为 127 开头的本地流量
        if ((dst_ip & 0xff) == 0x7f) {
            return 1;
        }
        
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);

        // 即将重定向流量至 Envoy，此处把重定向之前真正要发往的目的地信息记录下来，即原始目的地址
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;
        origin.flags = 1;
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin, BPF_ANY)) {
            return 0;
        }
        
        if (curr_pod_ip) {
            struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, _curr_pod_ip);
            if (pod) {
	            /* 根据各种 Exclude/Include Out Ports/Ranges 信息来判断是否还进一步向后执行；
	               podConfig 中的各种 Pod 配置信息是经由 Local IP Controller 获取的。
	             */
	            // ...
            }

            // 对于存在 Pod IP 的情况，将与 ctx 关联的 socket 绑定到 Pod 的 IP 地址上
            struct sockaddr_in addr = {
                .sin_addr =
                    {
                        .s_addr = curr_pod_ip,
                    },
                .sin_port = 0,    // 端口由内核随机指定一个未被使用的
                .sin_family = 2,  // aka. AF_INET
            };
            bpf_bind(ctx, &addr, sizeof(struct sockaddr_in))
            ctx->user_ip4 = localhost;  // 修改数据包目的地址
            
        } else {
            // 对于无法获取 Pod IP 的情况，目的地址为自定义地址
            // The reason we try the IP of the 127.128.0.0/20 segment instead of
            // using 127.0.0.1 directly is to avoid conflicts between the
            // quaternions of different Pods when the quaternions are
            // subsequently processed.
            ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));  // 修改数据包目的地址
            if (outip >> 20) {
                outip = 1;
            }
        }
        
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);  // 修改数据包目的端口，即 sidecar 的 15001 端口
    }
    
    // ...

    return 1;
}
```

2\. 在应用的 Socket 侧，当执行到 `sockops` eBPF 程序时，其会将当前 socket 和四元组保存在 `sock_pair_map` map 中，同时将四元组和对应流量的原始目的地址写入 `pair_original_dst` map 中。

```c
static inline int sockops_ipv4(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie_ops(skops);

    struct pair p;
    set_ipv4(p.sip, skops->local_ip4);
    p.sport = bpf_htons(skops->local_port);
    set_ipv4(p.dip, skops->remote_ip4);  // 在应用侧 socket，拿到的目的地址和端口已经是发往 envoy 15001 的地址和端口
    p.dport = skops->remote_port >> 16;

    struct origin_info *dst =
        bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        
        // ...
	    
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_ANY);
		bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST); // key 为四元组
    } else if (skops->local_port == OUT_REDIRECT_PORT ||
               skops->local_port == IN_REDIRECT_PORT ||
               skops->remote_ip4 == envoy_ip) {
        // 在 envoy 侧 socket，同样将其 socket 与对应的四元组写入 map
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    // ...
    return 0;
}
```

值得注意的是，该段程序由于挂载在 sockops 挂载点，故会有多次执行，根据不同的执行侧可以分为：处理应用侧 socket 和 envoy 侧的 socket。
当在 Sidecar envoy 侧执行时，四元组的原地址和原端口对应 envoy:15001，目的地址和目的端口对应于应用。envoy 侧的 socket 对应于 `cookie_original_dst` map 中不存在任何原始地址信息，故会落入上述程序的第二段 if 语句，即只更新 `sock_pair_map` ，保存当前四元组与 envoy 侧 socket 的映射关系，便于后期转发流量时使用。

3\. Envoy 接受到应有连接之后会调用 `get_sockopts` eBPF 程序获取当前连接的目的地址，该程序会依据四元组信息从 `pair_original_dast` map 中获取原始目的地址并保存。至此，出口向流量的连接建立完毕。

```c

__section("cgroup/getsockopt") int mb_get_sockopt(struct bpf_sockopt *ctx)
{
    // ...
	
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.dport = bpf_htons(ctx->sk->src_port);  // 15001 端口，作为四元组的目的端口，顺序交互是为了能通过四元组查找出原始地址信息
    p.sport = ctx->sk->dst_port;
    struct origin_info *origin;
    switch (ctx->sk->family) {
    case 2: // ipv4
        set_ipv4(p.dip, ctx->sk->src_ip4);  // envoy 地址，作为四元组的目的地址
        set_ipv4(p.sip, ctx->sk->dst_ip4);
        // 四元组准备完毕
        
        // 根据四元组获取上一步中保存的原始目的地址 
        origin = bpf_map_lookup_elem(&pair_original_dst, &p);
        if (origin) {
            // 重写当前 socket
            ctx->optlen = (__s32)sizeof(struct sockaddr_in);
            if ((void *)((struct sockaddr_in *)ctx->optval + 1) > ctx->optval_end) {
                return 1;
            }
            
            ctx->retval = 0;
            
            struct sockaddr_in sa = {
                .sin_family = ctx->sk->family,
                .sin_addr.s_addr = get_ipv4(origin->ip),
                .sin_port = origin->port,
            };
            *(struct sockaddr_in *)ctx->optval = sa;  // 写入请求选项的 buffer
        }
        break;
    case 10: // ipv6
        // ...
    }
    return 1;
}
```

4\. 在发送数据阶段，`redir` eBPF 程序会根据四元组信息，从 `sock_pair_map` 中读取到 Sidecar envoy 的 socket，并通过 `bpf_msg_redirect_hash` 直接对流量进行转发。

```c
__section("sk_msg") int mb_msg_redir(struct sk_msg_md *msg)
{
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.dport = bpf_htons(msg->local_port);
    p.sport = msg->remote_port >> 16; // 目的端口 15001 作为四元组的原端口，为了获取四元组对应的 socket 信息

    switch (msg->family) {
#if ENABLE_IPV4
    case 2:
        // ipv4
        set_ipv4(p.dip, msg->local_ip4);
        set_ipv4(p.sip, msg->remote_ip4);
        break;
#endif
#if ENABLE_IPV6
    case 10:
        // ipv6 ...
#endif
    }

    long ret = bpf_msg_redirect_hash(msg, &sock_pair_map, &p, BPF_F_INGRESS);
    return 1;
}
```

### 入口流量处理

入口流量的处理与出口流量类似，只需将目的地址的端口改为 15006 即可。

![merbridge-inbound.png](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-06/merbridge-inbound.png)

由于 eBPF 程序全局生效，对于不为 Istio 所管理的 Pod，就不允许外部流量向其建立连接。所以 Merbridge 维护了一个 `local_pod_ips` 的 map（通过 Local IP Controller 更新）。当 Merbridge 在做入口流量处理时，若目的地址不在该 map 中，则不做任何处理。

当外部流量抵达一个 Pod 时，只要其目的地址的 Pod 在当前 Node 所维护的 `local_pod_ips` 之中，并且不为当前处理 Pod 时，才需要将流量重定向到 Envoy 的 15006 端口。具体过程如下，主要还是修改流量的目的地址，并记录原始地址信息。其余的流程同出口流量处理，不再赘述。

```c
static inline int tcp_connect4(struct bpf_sock_addr *ctx)
{
    // ...
    if (uid != SIDECAR_USER_ID) {
        // 见上文
        // ...
    } else {
        __u32 _dst_ip[4];
        set_ipv4(_dst_ip, dst_ip);
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, _dst_ip);
        // 若目的地址非本地 Node 中的 Pod IP，则跳过处理
        if (!pod) {
            return 1;
        }

        // 目的地址在本地，但并非当前 Pod
        // 记录原始目的地址信息，以便后续修改数据包信息
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;

        if (curr_pod_ip) {
	        // 对于目的地址非当前 Pod 的流量，需要重定向数据包端口
            if (curr_pod_ip != dst_ip) {
                /* 根据各种 Exclude/Include Out Ports 信息来判断是否还进一步向后执行；
	               podConfig 中的各种 Pod 配置信息是经由 Local IP Controller 获取的。
	             */
                 // ...
	            
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);  // 修改目的端口为 15006
            }
            origin.flags |= 1;
        } else {
	        // 若 Pod IP 获取失败，则使用传统方式获取 Pod IP
            __u32 pid = bpf_get_current_pid_tgid() >> 32; // tgid
            void *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
            if (curr_ip) {
                if (*(__u32 *)curr_ip != dst_ip) {
                    ctx->user_port = bpf_htons(IN_REDIRECT_PORT);  // 修改目的端口为 15006
                }
                origin.flags |= 1;
            } else {
                // 若 Pod IP 仍然获取失败，envoy 向自身 pod 发送了流量
                origin.flags = 0;
                origin.pid = pid;
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);  // 修改目的端口为 15006
            }
        }
        
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin, BPF_NOEXIST)) {
            return 0;
        }
    }

    return 1;
}
```

## 小结

作为一个使用 eBPF 替代 iptables，并且加速 Istio 流量路径的项目，其不会对 Istio 有任何侵略式的修改。在完全卸载 Merbridge 后，Istio 还能依然保持使用 iptables 作为流量的劫持手段。从使用 eBPF 替代 iptables DNAT 的能力来说，`ORIGINAL_DST` 概念是贯穿全文的核心，其本质上就是记录被拦截流量的原始目的地址。

Merbridge 项目的整体规模虽然不大，但是非常具备学习意义，可以作为一个很好理解  eBPF 工作机理的入手项目。

## Reference

1. [https://merbridge.io/docs/overview/](https://merbridge.io/docs/overview/)
2. [https://arthurchiao.art/blog/bpf-advanced-notes-5-zh/](https://arthurchiao.art/blog/bpf-advanced-notes-5-zh/)
3. [https://istio.io/latest/docs/ops/deployment/requirements/#pod-requirements](https://istio.io/latest/docs/ops/deployment/requirements/#pod-requirements)
4. [https://github.com/libbpf/bpftool/blob/main/docs/bpftool-cgroup.rst](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-cgroup.rst)
5. [https://merbridge.io/blog/2022/03/01/merbridge-introduce/](https://merbridge.io/blog/2022/03/01/merbridge-introduce/)
