---
title: "Cilium CNI: tc ReloadDatapath 工作原理解析"
layout: article
key: cilium_cni_tc
tags:
- Network
- CNI
- Cilium
---

> 本文代码基于 Cilium HEAD [4093531](https://github.com/cilium/cilium/commit/40935318e344424be1ea96510c96427aef5134c3) 展开。

在 Cilium CNI 中，每当 CiliumEndpoint 被创建时，都会触发`Loader.CompileAndLoad`方法的执行。在[之前的文章中](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html#compileandload)提到过，Cilium 使用`tc`（traffic control）来将编译好的 BPF 程序加载到内核，但针对具体加载过程、加载内容并没有展开描述，因此本文借机来一探究竟。
```go
// pkg/datapath/loader/loader.go

func (l *Loader) CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	if ep == nil {
		log.Fatalf("LoadBPF() doesn't support non-endpoint load")
	}

	dirs := directoryInfo{
		Library: option.Config.BpfDir,     // /var/lib/cilium/bpf，存放 BPF 模版文件
		Runtime: option.Config.StateDir,   // /var/run/cilium，存放 endpoint 运行状态
		State:   ep.StateDir(),            // /var/run/cilium/state/{endpoint-id}
		Output:  ep.StateDir(),
	}
	return l.compileAndLoad(ctx, ep, &dirs, stats)
}

func (l *Loader) compileAndLoad(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo) error {
	err := compileDatapath(ctx, dirs, ep.IsHost(), ep.Logger(Subsystem))  // 编译 BPF 程序
	err = l.reloadDatapath(ctx, ep, dirs)  // 加载 BPF 程序
	return err
}
```

<!--more-->

## Reload Datapath
Cilium 使用`Loader.reloadDatapath`来完成 BPF 程序的加载工作：
```go
// pkg/datapath/loader/loader.go

func (l *Loader) reloadDatapath(ctx context.Context, ep datapath.Endpoint, dirs *directoryInfo) error {
	// 替换当前 BPF 程序
	objPath := path.Join(dirs.Output, "bpf_lxc.o")

	// endpoint 是否为 host endpoint
	if ep.IsHost() {
		objPath = path.Join(dirs.Output, "bpf_host.o")
		l.reloadHostDatapath(ctx, ep, objPath)  // 重载 cilium_host 上的 BPF 程序
	} else {
		progs := []progDefinition{{progName: "cil_from_container", direction: "ingress"}}

		if ep.RequireEgressProg() {
			progs = append(progs, progDefinition{progName: "cil_to_container", direction: "egress"})
		} else {
			err := RemoveTCFilters(ep.InterfaceName(), netlink.HANDLE_MIN_EGRESS)  // 移除接口 egress 方向上所有的 filters
		}

		finalize, err := replaceDatapath(ctx, ep.InterfaceName(), objPath, progs, "")  // 重载 endpoint 接口上的 BPF 程序
		defer finalize()
	}

	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsValid() {  // 获取 endpoint 的 ipv4 地址
			upsertEndpointRoute(ep, *iputil.AddrToIPNet(ip))
		}
		if ip := ep.IPv6Address(); ip.IsValid() {
			upsertEndpointRoute(ep, *iputil.AddrToIPNet(ip))
		}
	}

	return nil
}
```
其中，BPF 程序的重载根据 endpoint 属性的不同，分为了两种情况：

- 对于 host endpoint 来说，BPF 程序`bpf_host.o`的重载发生在 endpoint 所在宿主机的`cilium_host`设备上
  ```bash
  ~ tc filter show dev cilium_host ingress
  filter protocol all pref 1 bpf chain 0
  filter protocol all pref 1 bpf chain 0 handle 0x1 cil_to_host-cilium_host direct-action not_in_hw id 4203 tag fd128c0c744c0771 jited

  ~ tc filter show dev cilium_host egress
  filter protocol all pref 1 bpf chain 0
  filter protocol all pref 1 bpf chain 0 handle 0x1 cil_from_host-cilium_host direct-action not_in_hw id 4213 tag bc5f052f5017dabd jited
  ```

- 对于普通的 endpoint 来说，BPF 程序`bpf_lxc.o`的重载发生在 endpoint 的网络接口上
  ```bash
  ~ tc filter show dev lxc9fc12c71903b ingress
  filter protocol all pref 1 bpf chain 0
  filter protocol all pref 1 bpf chain 0 handle 0x1 cil_from_container-lxc9fc12c71903b direct-action not_in_hw id 4931 tag 4cfba610f154c365 jited
  ```

## Host Endpoint
有关 host endpoint 的定性非常简单，就是通过 labels 来判断的。并且在 Cilium 中，该 label 用于**特殊的预留（reserved）identity**：
```go
// pkg/endpoint/endpoint.go

func parseEndpoint(ctx context.Context, owner regeneration.Owner, ...) (*Endpoint, error) {
	// ...

	// 若有 key 为 "reserved:host" label 的 endpoint 即为 host endpoint
	ep.isHost = ep.HasLabels(labels.LabelHost)

	// ...
}
```
host endpoint 是一种特殊的 endpoint，可以将其认为是从 localhost 抽象的一个 endpoint。从它的配置可以看出，host endpoint 对应`cilium_host`网络接口。
```bash
~ kubectl -n kube-system exec cilium-k6rxc -- cilium endpoint get -l reserved:host
# ...
  "networking": {
    "addressing": [
      {}
    ],
    "host-mac": "be:00:72:df:07:5a",
    "interface-name": "cilium_host",  # 接口名
    "mac": "be:00:72:df:07:5a"        # 接口mac地址
  },
# ...
```
实际上，`cilium_host`接口对应的 ip 地址就是 [Cilium Internal IP](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html#cilium-internal-ip)：
```bash
~ ip addr
# ...
5: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 65535 qdisc noqueue state UP group default qlen 1000
    link/ether be:00:72:df:07:5a brd ff:ff:ff:ff:ff:ff
    inet 10.244.2.110/32 scope global cilium_host
# ...

~ kubectl get cn kind-worker
NAME                 CILIUMINTERNALIP   INTERNALIP   AGE
kind-worker          10.244.2.110       172.19.0.4   17h
```
值得注意的是，在 host 的根命名空间下，一共存在四个虚拟网络接口：

- `cilium_vxlan`，负责对数据包在 vxlan 中的解、封装操作
- `cilium_host`和`cilium_net`，它们实质上是一对 veth-pair
   - `cilium_host`用作节点所在集群子网的网关，因为在 [endpoint 生成的路由](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html#endpoint-%E8%B7%AF%E7%94%B1%E7%94%9F%E6%88%90)中，Cilium Internal IP 充当了 endpoint 的默认网关
- `lxc_health`，负责 endpoint 间的健康检查

### reloadHostDatapath
对于 host endpoint 来说，先通过`reloadHostDatapath`方法来准备所有需要被加载的 BPF 程序，最后再调用`replaceDatapath`函数完成对 BPF 程序的重载。有关`replaceDatapath`函数的分析，见后续章节描述。
```go
// pkg/datapath/loader/loader.go

func (l *Loader) reloadHostDatapath(ctx context.Context, ep datapath.Endpoint, objPath string) error {
	nbInterfaces := len(option.Config.GetDevices()) + 2  // default: 2
	symbols := make([]string, 2, nbInterfaces)
	directions := make([]string, 2, nbInterfaces)
	objPaths := make([]string, 2, nbInterfaces)
	interfaceNames := make([]string, 2, nbInterfaces)
	symbols[0], symbols[1] = "cil_to_host", "cil_from_host"
	directions[0], directions[1] = "ingress", "egress"
	objPaths[0], objPaths[1] = objPath, objPath
	interfaceNames[0], interfaceNames[1] = ep.InterfaceName(), ep.InterfaceName()

	if _, err := netlink.LinkByName("cilium_net"); err != nil {
		return err  // cilium_net 和 cilium_host 成对出现，若对端接口不存在，则直接返回错误
	} else {
		// 对于 cilium_net 接口来说，其只需要在 ingress 方向上加载 BPF 程序即可
		interfaceNames = append(interfaceNames, "cilium_net")
		symbols = append(symbols, "cil_to_host")
		directions = append(directions, "ingress")
		secondDevObjPath := path.Join(ep.StateDir(), "bpf_host_cilium_net.o")
		err := patchHostNetdevDatapath(ep, objPath, secondDevObjPath, "cilium_net", nil)  // 填充一些接口信息
		objPaths = append(objPaths, secondDevObjPath)
	}

	bpfMasqIPv4Addrs := node.GetMasqIPv4AddrsWithDevices()

	// 默认情况下该配置项为空，故一般不执行此循环
	for _, device := range option.Config.GetDevices() {
		if _, err := netlink.LinkByName(device); err != nil {
			continue
		}

		netdevObjPath := path.Join(ep.StateDir(), "bpf_netdev_"+device+".o")
		err := patchHostNetdevDatapath(ep, objPath, netdevObjPath, device, bpfMasqIPv4Addrs)
		objPaths = append(objPaths, netdevObjPath)
		interfaceNames = append(interfaceNames, device)
		symbols = append(symbols, "cil_from_netdev")
		directions = append(directions, "ingress")

		// ... 判断是否需要加载 cil_to_netdev 到接口 egress 方向
	}

	// 针对每个接口，分别重载属于该接口、接口方向的 BPF 程序
	for i, interfaceName := range interfaceNames {
		symbol := symbols[i]
		progs := []progDefinition{{progName: symbol, direction: directions[i]}}
		finalize, err := replaceDatapath(ctx, interfaceName, objPaths[i], progs, "")  // ***
		defer finalize()
	}

	return nil
}
```
在此方法的实现中，可以发现：针对 host endpoint，其不止在`cilium_host`接口的 ingress/egress 两个方向上都加载了 BPF 程序，还为其对端`cilium_net`的 ingress 方向也加载了 BPF 程序。最终，`cilium_host`和`cilium_net`形成如下图所示的一种关系：

![cilium-host-net](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-08-09/cilium-host-net.png)

其次，若用户通过`daemonConfig.devices`指定了 bpf_host 设备，则 Cilium 会专门为这些设备载入名为`bpf_netdev_${device}.o`的程序。但一般该功能只在宿主机启用防火墙或启动 BPF NodePort 等情况下才使用。
### bpf: cil-to-host
Cilium 在`cilium_host`接口上重载的两个 BPF 程序分别为：`cil-from-host`和`cil-to-host`。

其中，在 ingress 方向上，重载的`cil-from-host`BPF 程序存在以下调用栈（以 IPv4 为例）：
```
|- cil_to_host                             @ bpf/bpf_host.c
   |- ipv4_host_policy_ingress             @ bpf/lib/host_firewall.h
      |- ipv4_host_policy_ingress_lookup
      |- __ipv4_host_policy_ingress
```
在`ipv4_host_policy_ingress_lookup`中，先使用数据包的目的地址进行了 endpoint 的身份检查，并且只针对目的身份为`cilium_host`（即 host endpoint）的数据包进行后续 ingress policy 的执行：
```c
static __always_inline bool
ipv4_host_policy_ingress_lookup(struct __ctx_buff *ctx, struct iphdr *ip4, struct ct_buffer4 *ct_buffer)
{
	int l4_off, l3_off = ETH_HLEN;
	__u32 dst_sec_identity = WORLD_ID;
	struct remote_endpoint_info *info;
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;

	/* 获取目的地址所指 endpoint 的 identity */
	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
	if (info && info->sec_identity)
		dst_sec_identity = info->sec_identity;

	/* 只针对目的 ID 为 host 类型的 endpoint 施加 host policy 计算 */
	if (dst_sec_identity != HOST_ID)
		return false;

	/* 在 conntrack map 中寻找连接 */
	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	ct_buffer->ret = ct_lookup4(get_ct_map4(tuple), tuple, ctx, l4_off, CT_INGRESS,
				    &ct_buffer->ct_state, &ct_buffer->monitor);

	return true;
}
```
对于那些目的 endpoint 非 host 类型的数据包，则直接在`ipv4_host_policy_ingress`中返回`CTX_ACT_OK`，无需执行 后续函数。而对于那些参与 ingress policy 计算的数据包，则会执行`__ipv4_host_policy_ingress`：
```c
static __always_inline int
__ipv4_host_policy_ingress(struct __ctx_buff *ctx, struct iphdr *ip4,
			   struct ct_buffer4 *ct_buffer, __u32 *src_sec_identity,
			   struct trace_ctx *trace, __s8 *ext_err)
{
	struct ct_state ct_state_new = {};
	struct ct_state *ct_state = &ct_buffer->ct_state;
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;
	__u16 node_id = 0;
	int ret = ct_buffer->ret;
	int verdict = CTX_ACT_OK;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	struct remote_endpoint_info *info;
	bool is_untracked_fragment = false;
	__u16 proxy_port = 0;

	/* 根据源 IP 地址获取源 endpoint 的 identity */
	info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
	if (info && info->sec_identity) {
		*src_sec_identity = info->sec_identity;
		node_id = info->node_id;
	}

	/* 查询 policy 并计算该数据包能否通过 ingress 进入接口，返回判决结果 */
	verdict = policy_can_access_ingress(ctx, *src_sec_identity, HOST_ID, tuple->dport, tuple->nexthdr,
                                        is_untracked_fragment, &policy_match_type, &audited, ext_err, &proxy_port);

	/* 只有该连接被接受时，才在 conntrack map 中创建新的 CT 项 */
	if (ret == CT_NEW && verdict == CTX_ACT_OK) {
		ct_state_new.src_sec_id = *src_sec_identity;
		ct_state_new.node_port = ct_state->node_port;
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple,
				 ctx, CT_INGRESS, &ct_state_new, proxy_port > 0, false, ext_err);
		if (IS_ERR(ret)) return ret;
	}

out:
	/* 将数据包从 lxc 设备重定向到 host 设备 */
	ctx_change_type(ctx, PACKET_HOST);
	return verdict;
}
```
该函数主要通过`policy_can_access_ingress`**计算 ingress 上的 policy 是否允许数据包进入**。在 policy 匹配阶段，Cilium 先从 Map 中读取出 policy，再进行匹配。Cilium 将 policy 的匹配分为了六种优先级（从 1～6 优先度依次递减，如下表所示）。Policy 的每种优先级都由三个匹配维度来描述，其中 **ID 属于 L3 匹配特征，协议和端口均属于 L4 匹配特征**。这三个匹配维度正好描述了 Cilium 所定义的 NetworkPolicy 类型的 CRD，以`CiliumClusterwideNetworkPolicy`为例，[其 ingress 的 spec](https://doc.crds.dev/github.com/cilium/cilium/cilium.io/CiliumClusterwideNetworkPolicy/v2@v1.14.0-snapshot.4#spec-ingress) 都是围绕这三个维度展开的。

| Precedence | Policy Match | Match Type |
| --- | --- | --- |
| 1 | id/proto/port | L3/L4 |
| 2 | ANY/proto/port | L4-only |
| 3 | id/proto/ANY | L3-proto |
| 4 | ANY/proto/ANY | Proto-only |
| 5 | id/ANY/ANY | L3-only |
| 6 | ANY/ANY/ANY | All |

## Endpoint
无论 endpoint 的类型如何，它们最终都要执行`replaceDatapath`函数。
### replaceDatapath
该函数首先解析 BPF ELF 文件为 CollectionSpec，并将其加载至内核。由于每次都是将 CollectionSpec 固定（pin）到 bpffs 的一个路径上，并加载为一个 Map，所以只要在 Map 类型、key/value 大小、flags 和最大实例数这几个特征不变的情况下，Cilium 可以复用同一个 Map。但若发生改变，则需进行 bpffs Map 的迁移操作（`BPFFSMigration`，即 re-pin）。
```go
// pkg/datapath/loader/netlink.go

func replaceDatapath(ctx context.Context, ifName, objPath string, progs []progDefinition, xdpMode string) (func(), error) {

	link, err := netlink.LinkByName(ifName)

	// 从磁盘加载 eBPF ELF 文件，并解析为 CollectionSpec
	spec, err := bpf.LoadCollectionSpec(objPath)

	for _, prog := range progs {
		if spec.Programs[prog.progName] == nil {  // 查询重载的程序是否包含 BPF 程序中
			return nil, // not-found
		}
	}

	// 加载 CollectionSpec 至内核，并 pin 在 bpffs 的 TCGlobalsPath 路径上
	finalize := func() {}
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
	}
	coll, err := bpf.LoadCollection(spec, opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// 若路径上原有的 spec 与现加载的 spec 不同，就尝试重新加载新的 spec
		err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec)

		finalize = func() {
			bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, false)  // 删除现有加载 maps
		}

		// 上述重新加载完毕后，再次重试加载 CollectionSpec
		coll, err = bpf.LoadCollection(spec, opts)
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Verifier error
	}
	defer coll.Close()

	for _, prog := range progs {
		// 将程序挂载到接口上
		if err := attachProgram(link, coll.Programs[prog.progName], prog.progName, directionToParent(prog.direction), xdpModeToFlag(xdpMode)); err != nil {
			bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, true)  // 回滚到原有 maps
			return nil, err
		}
	}

	return finalize, nil
}
```
挂载 BPF 程序的工作，由`attachProgram`函数完成。该函数在不指定`xdpFlags`的情况下，**默认将 BPF 程序挂载到网络接口上**，而非 XDP 上。接口的排队规则（qdisc）被定义为`clsact`类型，所有的 BPF 程序都以 FD 的形式关联到 filter，并挂载到接口的 qdisc 之上。值得注意的是，每个 BPF 程序都启用了`direct-action`模式，即允许 classifier 和 action 作为一个整体运行。
```go
func attachProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32, xdpFlags uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	if xdpFlags != 0 {
		// 挂载程序到 XDP
		netlink.LinkSetXdpFdWithFlags(link, prog.FD(), int(xdpFlags))
		return nil
	}

	err := replaceQdisc(link)  // 替换接口现有的 clsact qdisc

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,  // 启用 direct-action 模式
	}

	err := netlink.FilterReplace(filter)  // 替换现有的 tc filter

	return nil
}
```
挂载的结果都可以通过 tc 命令观察到：
```bash
~ tc qdisc show dev lxc0a9a490923c0
qdisc noqueue 0: root refcnt 2
qdisc clsact ffff: parent ffff:fff1

~ tc filter show dev lxc0a9a490923c0 ingress
filter protocol all pref 1 bpf chain 0
filter protocol all pref 1 bpf chain 0 handle 0x1 cil_from_container-lxc0a9a490923c0 direct-action not_in_hw id 2562 tag 8b558784f2a7a755 jited
```
### bpf: cil-from-container
`cil-from-container`是 Cilium 加载到 endpoint 接口 ingress 方向上的 BPF 程序。该程序存在以下调用栈（以 IPv4 为例）：
```
|- cil_from_container                                       @ bpf/bpf_lxc.c
   |- ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC)          @ bpf/lib/maps.h
           ||         \                    /
      tail_call_static(ctx, &CALLS_MAP, index)              @ bpf/include/bpf/tailcall.h
                                 |
                       struct bpf_elf_map __section_maps CALLS_MAP = { // 每个 endpoint 用于内部 tail calls 的私有 map
                         .type       = BPF_MAP_TYPE_PROG_ARRAY,  // 特殊类型的 Map，存储自定义 index 到 bpf_program_fd 的映射
                         .id         = CILIUM_MAP_CALLS,
                         .size_key   = sizeof(__u32),
                         .size_value = sizeof(__u32),
                         .pinning    = PIN_GLOBAL_NS,
                         .max_elem   = CILIUM_CALL_SIZE,
                       };
```
最终该程序执行 [tail calls](https://docs.cilium.io/en/stable/bpf/architecture/#tail-calls)，将传入的各参数值通过汇编代码加载到各寄存器内，并<mark>调用一个标号为 12 的函数（？）</mark>。
```c
// bpf/include/bpf/tailcall.h

static __always_inline __maybe_unused void
tail_call_static(const struct __ctx_buff *ctx, const void *map, const __u32 slot)
{
	if (!__builtin_constant_p(slot))  // 检查 slot 变量值是否合法
		__throw_build_bug();

	asm volatile("r1 = %[ctx]\n\t"      // 将变量 ctx 的值加载到寄存器 r1 内
		     "r2 = %[map]\n\t"      // 将变量 map 的值加载到寄存器 r2 内
		     "r3 = %[slot]\n\t"     // 将变量 slot 的值加载到寄存器 r3 内
		     "call 12\n\t"          // 调用函数
		     :: [ctx]"r"(ctx), [map]"r"(map), [slot]"i"(slot)  // 输出操作数列表
		     : "r0", "r1", "r2", "r3", "r4", "r5");            // 输入操作数列表
}
```
由`CILIUM_CALL_IPV4_FROM_LXC`作为`CALLS_MAP`的 index 时，其对应的 tail calls 函数如下所示。该函数主要先对数据包执行一些验证和过滤操作，之后通过 tail calls 的方式执行：对每个数据包进行到 service 的负载均衡，对应`__per_packet_lb_svc_xlate_4`函数，由于该函数内容并非本文重点，故略。
```c
// bpf/bpf_lxc.c

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
	int ret = __tail_handle_ipv4(ctx, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(/*...*/);
	return ret;
}

static __always_inline int __tail_handle_ipv4(struct __ctx_buff *ctx,
					      __s8 *ext_err __maybe_unused)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))  // 验证包数据部分长度
		return DROP_INVALID;

#ifndef ENABLE_IPV4_FRAGMENTS  // 在 IPv4 分片未启用时，若接收到了 IPv4 分片报文，则直接丢弃
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))  // 验证源 ip 地址是否有效
		return DROP_INVALID_SIP;

#ifdef ENABLE_PER_PACKET_LB
	/* 会内部执行 tailcall 或返回错误 */
	return __per_packet_lb_svc_xlate_4(ctx, ip4, ext_err);
#else
	/* 不会执行 tailcall */
	return tail_ipv4_ct_egress(ctx);
#endif /* ENABLE_PER_PACKET_LB */
}
```
另外值得注意的一个点就是，`is_valid_lxc_src_ipv4`是如何验证源 IP 地址是否有效的？此函数是通过比较数据包的源地址与`LXC_IPV4`宏的值来验证的。`LXC_IPV4`这个宏是在 tc ReloadDatapath 之前，通过 [regenerate 方法](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html#regenerate)写入到`/var/run/cilium/state/${endpoint-id}/ep_config.h`中的。
```bash
~ cat /var/run/cilium/state/1332/ep_config.h | grep IP
 * IPv4 address: 10.244.2.149
DEFINE_U32(LXC_IPV4, 0x9502f40a);	/* 2499998730 */
#define LXC_IPV4 fetch_u32(LXC_IPV4)
```
### Endpoint Routes
在 Native Kubernetes 中运行 Cilium 时，由于`reloadDatapath`方法中`ep.RequireEgressProg()`和`ep.RequireEndpointRoute()`的返回值都是由 cilium-daemon 的`EnableEndpointRoutes`配置项控制的（该配置项**默认情况下是关闭的**），即表明对于非 host 类型的 endpoint 来说，**BPF 程序的重载一般情况下只发生在 endpoint 接口的 ingress 方向**。
```go
// daemon/cmd/endpoint.go

func (d *Daemon) createEndpoint(ctx context.Context, owner regeneration.Owner, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error) {
	if option.Config.EnableEndpointRoutes {  // default: "false"

		// 是否对每个 endpoint 都插入一条路由，而非使用经过 cilium_host 的路由
		epTemplate.DatapathConfiguration.InstallEndpointRoute = true  // 对应 RequireEndpointRoute()

		// 由于直接通过 endpoint 的接口路由，绕过了 cilium_host 接口，所以 BPF 程序需要挂载在 endpoint 接口的 egress 方向
		epTemplate.DatapathConfiguration.RequireEgressProg = true  // 对应 RequireEgressProg()

		// ...
	}
	// ...
}
```
由于 Cilium 可以接入各公有云平台，所以若当使用公有云提供的网络服务时，`EnableEndpointRoutes`配置项才会被启用。以 GKE 为例，其可在 Cilium 运行为 Native-Routing 的模式下使用 Google Cloud Network（GCN），[其中就有一项配置](https://docs.cilium.io/en/stable/network/concepts/routing/#id6)为`enable-endpoint-routes: true`。

在 Native-Routing 模式下，Cilium 会代理所有**不是发往另一个 local endpoint 的**数据包至 Linux 内核中的路由子系统。这意味着被路由的数据包就是像从本地进程发送出去的数据包一样，这也就要求集群内所有节点连接的网络层必须有路由`PodCIDRs`地址的能力，而 GCN 恰好就有此种能力。

![native-routes-gke](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-08-09/cilium-native-routes-gke.png)

观察 Native-Routing 模式下的路由表，可以发现其每项都由一个 endpoint 组成。而对比 Cilium [默认模式下的路由表](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html#endpoint-%E8%B7%AF%E7%94%B1%E7%94%9F%E6%88%90)（`enable-local-node-route: true`），可见其路由项绕过了`cilium_host`设备，转而是直接通过 endpoint 的接口路由。所以 Cilium 为此种情况下 endpoint 接口的 egress 方向也做了 BPF 程序的重载。

## 总结
本文从 host endpoint 与 endpoint 两种类型的 BPF 程序重载展开分析，并鸟瞰了两种加载的 BPF 程序代码。虽然 tc ReloadDatapath 是 Cilium CNI 工作的其中一步，但是也存在很多值得探讨的地方。本文只是以微观、局部的视角对 tc 的工作展开了分析，并没有对 Cilium 宏观、整体的过程展开描述，着实由于作者水平有限，浅尝辄止。若分析有误、考虑不全，望批评指正。

## Reference

1. [https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html](https://shawnh2.github.io/post/2023/07/18/cilium-cni-walk-through.html)
2. [https://docs.cilium.io/en/stable/gettingstarted/terminology/#reserved-labels](https://docs.cilium.io/en/stable/gettingstarted/terminology/#reserved-labels)
3. [https://docs.cilium.io/en/stable/network/ebpf/intro/](https://docs.cilium.io/en/stable/network/ebpf/intro/)
4. [https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control](https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control)
5. [https://docs.cilium.io/en/stable/network/concepts/routing/](https://docs.cilium.io/en/stable/network/concepts/routing/)
6. [https://docs.cilium.io/en/stable/bpf/architecture/](https://docs.cilium.io/en/stable/bpf/architecture/)
7. [https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html)
8. [https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
9. [http://arthurchiao.art/blog/cilium-code-cni-create-network/#93-reload-datapath](http://arthurchiao.art/blog/cilium-code-cni-create-network/#93-reload-datapath)
10. [https://www.ebpf.top/post/bpf2pbpf_tail_call/](https://www.ebpf.top/post/bpf2pbpf_tail_call/)
