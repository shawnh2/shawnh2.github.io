---
title: Multus CNI 工作原理解析
layout: article
key: multus_cni
tags:
- Network
- CNI
- Kubernetes
---

> 本文代码基于 [Multus CNI v3.7](https://github.com/k8snetworkplumbingwg/multus-cni/tree/release-3.7) 展开。

Multus CNI 专门负责为 Pod 增加新的网络接口，以接入不同类型的网络，比如 macvlan 等等。而且它的定位是个 Meta CNI，即可代理调用其他 CNI 集群网络插件，因此可以与 calico、flannel 等 CNI 共存。

![multus-cni-arch](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-10/multus-cni-arch.png)

<!--more-->

## CNI 协议能力

首先介绍一些在 Multus CNI 中使用到的 CNI 协议相关的内容。

### 操作命令

CNI 插件是负责配置容器网络接口的，它可以被分为两大类：

- 接口型插件，在容器内创建一个网络接口并保证其连通性
- 链式插件，即调整现有网络接口的配置

CNI 协议的参数是通过系统环境变量传入 CNI 插件的，[协议参数有很多](https://www.cni.dev/docs/spec/#parameters)，以`CNI_COMMAND`为例，其定义了四种 CNI 插件的操作行为：`ADD, DEL, CHECK, VERSION`。

对于 ADD 命令，其所需参数如下。CNI 插件要在容器的`CNI_NETNS`命名空间中：
- 创建由`CNI_IFNAME`定义的接口，或
- 调整由`CNI_IFNAME`定义的接口配置

```bash
required: CNI_COMMAND, CNI_CONTAINERID, CNI_NETNS, CNI_IFNAME
optional: CNI_ARGS, CNI_PATH
```

对于 DEL 命令，其所需参数如下。CNI 插件需要：
- 在容器的`CNI_NETNS`命名空间中删除由`CNI_IFNAME`定义的接口，或
- 撤销 ADD 命令所带来的改变

```bash
required: CNI_COMMAND, CNI_CONTAINERID, CNI_IFNAME
optional: CNI_NETNS, CNI_ARGS, CNI_PATH
```

### 插件委托机制

即 delegate 机制，这里暂且称之为委托机制。

这里所指的 CNI 插件不是像 flannel、calico 这样的 CNI 网络插件，而是执行一些基础网络功能的[可执行二进制文件](https://github.com/containernetworking/plugins)。引入委托机制的原因是，将所有 CNI 网络插件都会用到的基础网络功能专门抽象出来，不用每个插件都去编写相同的功能，比如 IPAM 相关的。
将基础网络能力与 CNI 网络插件解耦，减轻实现负担。

为保证所委托的 CNI 插件可正常执行，调用方需要：
- 在`CNI_PATH`环境变量指定的目录下寻找 CNI 插件的可执行二进制文件（这个变量值一般情况下为`/opt/cni/bin`）
- 在与 CNI 网络插件相同的环境和配置下执行该二进制文件
- 保证被委托的 CNI 插件的 stderr 是调用方执行时的 stderr，即错误会向上传播

## Multus CNI 组件

### multus-shim

一个做多插件的地方，也是 multus-cni 的本质，它读取其他 CNI 插件的 netconf 配置，并调用它们。

multus-shim 的整个执行也只是实现了 CNI 协议的`CNI_COMMAND`这一个参数，并拥有其四种行为（ADD、DEL、CHECK、VERSION）。这些命令的实现都通过 CNI 定义的接口类型`skel.PluginMain`注册，定义了 CNI 的执行内容如下：

```go
skel.PluginMain(
	func(args *skel.CmdArgs) error {
		return api.CmdAdd(args)
	},
	func(args *skel.CmdArgs) error {
		return api.CmdCheck(args)
	},
	func(args *skel.CmdArgs) error {
		return api.CmdDel(args)
	},
	cniversion.All, "meta-plugin that delegates to other CNI plugins")

// func definition
func PluginMain(cmdAdd, cmdCheck, cmdDel func(_ *CmdArgs) error, versionInfo version.PluginInfo, about string)
```

除了`VERSION`命令外，其他命令的 handler 均都**只进行**发送请求的工作，其本质上都调用了下述方法：

```go
func postRequest(args *skel.CmdArgs) (*Response, string, error) {
	// args 类型由 CNI 提供，其保存了所有有关 CNI 的配置参数，包括来自 stdin 和 os env 的
	// 其中 stdin 来源的配置是以 json 形式保存的

	// shimConfig 就是把 stdin 来源的 json 配置给转化为一个结构体使用
	multusShimConfig, err := shimConfig(args.StdinData)

	// 创建一个由 CNI 配置参数填充的 request，其中将 os env 来源的环境变量参数转化成 map 保存
	cniRequest, err := newCNIRequest(args)

	// 在 unix socket 上通过 JSON + HTTP 的形式发送 CNI 请求到 CNI server（即下文 multus-daemon）
	// 其中 http://dummy/cni 只是个七层请求 url，四层传输协议实际使用的还是 socket
	// socket 的默认路径为 /run/multus/multus.sock，MultusSocketDir 默认路径是 /run/multus/，socket 名为 multus.sock，
	body, err := DoCNI("http://dummy/cni", cniRequest, SocketPath(multusShimConfig.MultusSocketDir))
                         \
                          \
                          func DoCNI(url string, req interface{}, socketPath string) ([]byte, error) {
                              data, err := json.Marshal(req)
                              client := &http.Client{
                                  Transport: &http.Transport{
                                      Dial: func(proto, addr string) (net.Conn, error) {
                                          return net.Dial("unix", socketPath)
                                      },
                                  },
                              }
                              resp, err := client.Post(url, "application/json", bytes.NewReader(data))
                              body, err := io.ReadAll(resp.Body)
                              if resp.StatusCode != http.StatusOK {
                                  return nil, err
                              }
                              return body, nil
                          }


                            // github.com/containernetworking/cni/pkg/types/100/types.go #L85
                            // Result is what gets returned from the plugin (via stdout) to the caller
                            type Result struct {
                                CNIVersion string         `json:"cniVersion,omitempty"`
                                Interfaces []*Interface   `json:"interfaces,omitempty"`
                                IPs        []*IPConfig    `json:"ips,omitempty"`
                                Routes     []*types.Route `json:"routes,omitempty"`
                                DNS        types.DNS      `json:"dns,omitempty"`
                            }
                           /
                          /
	response := &Response{}

	// resp 回应的即为一个 pod 的所有网络配置信息，详见 https://www.cni.dev/docs/spec/#success
	if len(body) != 0 {
		json.Unmarshal(body, response)
	}
	return response, multusShimConfig.CNIVersion, nil
}
```

### multus-daemon
在 multus-cni 部署后，其在 kube-system 命名空间下会为集群中的每个节点启动一个 daemonset。该资源负责接受来自 multus-shim 的请求并处理，为 pod 创建网络接口。

此 daemonset 本质上是一个 http 服务器，其中包裹了 k8s-client 用于和 k8s 交互。该服务器的 listener 监听`/run/multus/multus.sock`端口，并只提供了三个服务接口：`/cni`, `/delegate`, `/healthz`：

- `/cni`负责处理来自 multus-shim 的 CNI 请求
- `/delegate`负责处理来自 <mark>hotplug (?)</mark> 的委托请求

以`/cni`接口为例，multus-cni 主要功能由该接口提供，该接口对应的 handler 只处理 POST 类型的 CNI 请求：

```go
func (s *Server) handleCNIRequest(r *http.Request) ([]byte, error) {
	var cr api.Request
	b := io.ReadAll(r.Body)
	json.Unmarshal(b, &cr)
	// 提取 CNI 命令参数，返回 CNI_COMMAND 类型（ADD、DEL、CHECK）与相关 CNI 参数
	cmdType, cniCmdArgs, err := extractCniData(&cr, s.serverConfig)
	                                \
                                         \
                                          func extractCniData(cniRequest *api.Request, overrideConf []byte) (string, *skel.CmdArgs, error) {
                                            cmd, ok := cniRequest.Env["CNI_COMMAND"]
                                            // 收集 CNI 相关参数
                                            cniCmdArgs := &skel.CmdArgs{}
                                            cniCmdArgs.ContainerID, ok = cniRequest.Env["CNI_CONTAINERID"]
                                            cniCmdArgs.Netns, ok = cniRequest.Env["CNI_NETNS"]
                                            cniCmdArgs.IfName, ok = cniRequest.Env["CNI_IFNAME"]
                                            if !ok {cniCmdArgs.IfName = "eth0"} // 默认使用 eth0 接口
                                            cniArgs, found := cniRequest.Env["CNI_ARGS"]
                                            cniCmdArgs.Args = cniArgs
                                              cniCmdArgs.StdinData = cniRequest.Config
                                            return cmd, cniCmdArgs, nil
                                          }


        // 提取 k8s 运行时参数，包括新建 pod 的 namespace、name、infra_container_id、pod uid 这4个参数
	k8sArgs, err := kubernetesRuntimeArgs(cr.Env, s.kubeclient)
	// 处理 CNI 请求,对来自 multus-shim 不同类型的命令执行不同操作
	result, err := s.HandleCNIRequest(cmdType, k8sArgs, cniCmdArgs, s.exec, s.kubeclient)
	                        \
                                 \
                                  func (s *Server) HandleCNIRequest(cmd string, k8sArgs *types.K8sArgs, cniCmdArgs *skel.CmdArgs, exec invoke.Exec, kubeClient *k8s.ClientInfo) ([]byte, error) {
                                      switch cmd {
                                      case "ADD":
                                          result, err = cmdAdd(cniCmdArgs, k8sArgs, exec, kubeClient)
                                      case "DEL":                 	                         \
                                          err = cmdDel(cniCmdArgs, k8sArgs, exec, kubeClient)     ---> // 最后都是调用 multus pkg 下的方法
                                      case "CHECK":                                              /
                                          err = cmdCheck(cniCmdArgs, k8sArgs, exec, kubeClient)
                                      default: // unknown error
                                      }
                                      return result, nil
                                  }

	return result, nil
}
```

以处理 ADD 命令请求的 handler 为例，`cmdAdd`最终调用`multus.CmdAdd`函数，该函数主要实现逻辑为：

```go
func CmdAdd(args *skel.CmdArgs, exec invoke.Exec, kubeClient *k8s.ClientInfo) (cnitypes.Result, error) {
	n, err := types.LoadNetConf(args.StdinData)
	kubeClient, err = k8s.GetK8sClient(n.Kubeconfig, kubeClient)
	k8sArgs, err := k8s.GetK8sArgs(args)

	// checking default network whether working ...

	pod, err := GetPod(kubeClient, k8sArgs, false)
	var resourceMap map[string]*types.ResourceInfo
	if n.ClusterNetwork != "" {
		resourceMap, err = k8s.GetDefaultNetworks(pod, n, kubeClient, resourceMap)
		// First delegate is always the master plugin
		n.Delegates[0].MasterPlugin = true
	}

	// 尝试加载 pod 的 cni 网络委托
	_, kc, err := k8s.TryLoadPodDelegates(pod, n, kubeClient, resourceMap)
	// 缓存 multus config 及其委托
	saveDelegates(args.ContainerID, n.CNIDir, n.Delegates)

	var result, tmpResult cnitypes.Result
	var netStatus []nettypes.NetworkStatus
	for idx, delegate := range n.Delegates {
		ifName := getIfname(delegate, args.IfName, idx)
		rt, cniDeviceInfoPath := types.CreateCNIRuntimeConf(args, k8sArgs, ifName, n.RuntimeConfig, delegate)
		netName := delegate.Conf.Name
		if netName == "" {netName = delegate.ConfList.Name}
		tmpResult, err = DelegateAdd(exec, kubeClient, pod, delegate, rt, n)
		// if err != nil，即委派调用失败，要删除有关该 CNI 插件的网络信息

		if delegate.MasterPlugin || result == nil {
			result = tmpResult
		}

		// create the network status, only in case Multus as kubeconfig ...
	}

	// set the network status annotation in apiserver, only in case Multus as kubeconfig ...

	return result, nil
}
```

- 首先加载 NetConf 配置与 K8s client 及其参数
  - 这里的 NetConf 配置从`/opt/cni/net.d`中加载，Multus CNI 安装后会植入一个优先级最高（文件名以`00`开头）的配置文件，配置文件内容如下所示：
```bash
{
    "capabilities":{"portMappings":true},
    "cniVersion":"0.3.1",
    "logLevel":"verbose",
    "name":"multus-cni-network",
    "clusterNetwork":"/host/etc/cni/net.d/10-calico.conflist",
    "type":"multus-shim",
    "socketDir":"/host/run/multus/"
}
```

- 获取 pod 信息并执行默认网络插件，即集群默认 CNI 网络插件：flannel、calico 等
  - 默认网络插件在 Multus 中被称之为即 Master 插件，由配置文件中的`clusterNetwork`字段指示
- 尝试解析并缓存一个 pod 的所有 CNI 委托（除了 Master 插件之外的其余在 Multus 中都被称之为 Minion 插件），这些委托信息是从 pod 的 annotation 字段加载的
  - 可选环节：尝试加载键为`v1.multus-cni.io/default-network`的默认 pod 网络配置；这个可选环节比较特殊，实际使用场景为集群中有多套集群网络可用时，可以给 pod 指定默认要使用的集群网络，不指定该字段就使用上述加载的默认网络配置；若要成功使用该字段功能，则需要将所有的集群网络被 NetworkAttachmentDefinition CRD 定义。该配置的使用示例如下：
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-example
annotations:
 v1.multus-cni.io/default-network: calico-conf
```
  - 加载键为`k8s.v1.cni.cncf.io/networks`的 NetworkAttachmentDefinition 的 CRD 资源（Multus CNI 的 CRD）配置
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-example
annotations:
 k8s.v1.cni.cncf.io/networks: network-conf@eth1
```

- 最后再针对之前找到的每个 CNI 委托，进行委托的调用


#### 委托调用

![workflow](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-05-10/multus-cni-workflow.png)

执行委托调用函数的大致逻辑如下所示，其本质还是调用了 CNI 的 ADD 命令方法，只不过是指明了执行哪个 CNI 插件的 ADD 操作：

```go
func DelegateAdd(exec invoke.Exec, kubeClient *k8s.ClientInfo, pod *v1.Pod, delegate *types.DelegateNetConf, rt *libcni.RuntimeConf, multusNetconf *types.NetConf) (cnitypes.Result, error) {
	// 验证网络接口名，即通过调用 netlink 查看该命名空间下是否存在该名字的接口
	validateIfName(rt.NetNS, rt.IfName)

	if delegate.MacRequest != "" || delegate.IPRequest != nil {
		if delegate.MacRequest != "" {
			// 验证 Mac address
			_, err := net.ParseMAC(delegate.MacRequest)
			rt.Args = append(rt.Args, [2]string{"MAC", delegate.MacRequest})
		}

		if delegate.IPRequest != nil {
			// 验证 IP address
			for _, ip := range delegate.IPRequest {
				if strings.Contains(ip, "/") {net.ParseCIDR(ip)}
			    else {net.ParseIP(ip)}
			}
			ips := strings.Join(delegate.IPRequest, ",")
			rt.Args = append(rt.Args, [2]string{"IP", ips})
		}
	}

	// 通过 CNI 调用被委托的插件，获取 CNI_PATH 路径，并调用 CNI 的 AddNetwork 方法为 pod 增加一个网络
	result, err := confAdd(rt, delegate.Bytes, multusNetconf, exec)
                      |
                      cniNet.AddNetwork()
                                |
                                (c *CNIConfig).addNetwork()
                                             |
                                             invoke.ExecPluginWithResult()
                                                            |
                                                            // 上述调用链均为 libcni 中的方法，该方法位于 pkg/server/exec_chroot.go
                                                            // 所做工作就是开启了一个命令行的执行，stdin、stderr、os env 都得到了处理
                                                            (e *ChrootExec).ExecPlugin()

	// 从 result 中获取所有 IP 地址，并置 pod 事件 ...

	return result, nil
}
```

`/delegate` 接口对应的 handler 也有四种命令类型，且其中的 ADD 类型对应的就直接是`DelegateAdd`这个方法。<mark>但目前我没有好像还没有找到使用到该接口的地方</mark>。

## 总结

总体来讲，Multus CNI 其实就是一个能够执行多个 CNI 委托的插件。从它的视角来看，它其实一定程度上也把 flannel、calico 等集群网络插件也视为了一个委托（执行`ls /opt/cni/bin`可以发现 calico 其实也以二进制形式出现）。

安装过 Multus CNI 的集群节点，会由 Multus 接管 CNI 的请求并由 multus-shim 发出代理 CNI 请求到 multus-daemon。执行网络接口创建与配置时，是按照先 Master 再 Minion 插件的方式，这也反映出默认集群网络插件创建的网络接口是整个 K8s 集群通信的基础，这一点是 Multus CNI 不可改变的。

## Reference

1. [https://www.cni.dev/docs/spec/#container-network-interface-cni-specification](https://www.cni.dev/docs/spec/#container-network-interface-cni-specification)
2. [https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/quickstart.md](https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/quickstart.md)

