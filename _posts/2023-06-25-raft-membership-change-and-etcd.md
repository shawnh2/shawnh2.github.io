---
title: Raft 的成员变更与 Etcd 的实现
layout: article
tags:
- Distributed System
---


> 本文配合 [Etcd v3.4](https://github.com/etcd-io/etcd/tree/release-3.4) 的实现来分析 Raft 协议中有关成员变更的内容。

集群的成员变化即是集群配置的变化。Raft 允许在一个集群不重启的前提下，自动化地对一个集群的配置进行变更。
## 单成员变更
### 安全性
对一个集群配置的变更而言，首先要考虑的就是安全性，即不破坏集群的大多数（majorities）。若在集群上每次只增加或删除一个 server，无论原始集群的个数是奇数还是偶数，一个旧集群的大多数和一个新集群的大多数必然会产生一个重叠，如下图所示。这个重叠就避免了一个集群被分离为两个大多数集群，因为它同时拥有向两端大多数的投票权，若新配置在集群中没有被复制到大多数，它的一票还是会决定集群继续使用旧配置；若新配置在集群中被复制到了大多数，它的一票就会将集群的配置切换为新配置。这种切换可以是直接切换，因为是安全的。

![overlap](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/membership-overlap.png)

<!--more-->

集群的配置是以一种特殊的 log entry 存储和通信的。在上述情况中，Raft 指出，server 总是使用自己 log 中记录的最新配置，无论该配置是否已经提交（committed）。即新配置往往在抵达 server 的 log 中时就开始生效，一旦新配置的 log entry 被提交（committed），就意味着新配置的变更已经完成，此时 leader 就会知道大多数节点已经采用了新配置。
### 可用性
#### 进度追赶
当一个 server 在加入集群后，其不会存储任何 log entries，而在此 server 同步 log entries 期间，集群是最容易产生不可用情况的。比如，在一个由 3 台 server 组成的集群中，加入一个 server 的同时一个原有的 server 挂了，会导致集群暂时不可用。因为对于一次 log entry 的提交而言，leader 需要 3 个 follower 的提交，才认为大多数 server 接受该 log entry。但是原有的 server 挂了并且新 server 距离提交新的 log entry 又很远，所以会存在一段不可用期。

![progress](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/progress.png)

为了避免这段不可用期，Raft 在配置变更之前，**引入了一个新的状态**，即新加入的 server 不能进行投票，只能接收 leader 的日志复制。并当新 server 赶上集群的整体进度后，leader 才能决定是否进行配置变更。除此之外，leader 还需负责终止配置的变更，如果新 server 不可用（可能地址或端口配置错误）或复制进度过慢（可能永远赶不上整体进度）的话。**在 etcd 的实现中，把处于此种状态的新 server 称之为 learner。**
```go
// raft/raft.go

func (r *raft) promotable() bool {
	pr := r.prs.Progress[r.id]
	return pr != nil && !pr.IsLearner  // 处于 learner 状态的节点不能参加选举
}
```
关于 learner 如何追赶集群的整体进度，有两个点需要注意。第一，log entries 是以何种粒度从 leader 复制到 learner；第二，leader 如何判断复制到何种程度才算达到整体进度。

针对第一点，需要注意的是一次复制的日志不能过大，否则可能造成 leader 心跳包的拥塞，导致 election timeout 并开启新一轮的选举。

![large-snapshot](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/large-snapshot.png)

针对第二点，Raft 将复制到新成员的 log entries 分成了不同的轮数（rounds），如下图所示。每轮中 leader 的所有 log entries 都会被复制到 learner 上，在本轮复制期间，leader 新提交的 entries 会被放到下轮再去复制。随着复制过程的持续进行，每轮复制的时间都会变短。经过一定的轮数后，若最后一轮复制的时间比 election timeout 小，leader 才会将 learner 加入到集群中，并认为 learner 已经处于集群的整体进度了；否则，leader 会终止本次配置的变更。

![round](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/round.png)

#### Leader 移除
当 server 发生移除，并且移除的又恰好是 leader 时，可以让 leader 先切换为 follower，即将 leader 卸任，之后就和移除一个普通的 server 处理一样了。

Raft 指出，**leader 的身份切换需要在新配置提交（committed）之后进行**。如果在新配置提交之前进行，原来的 leader 很有可能再次被票选为现任 leader。以下图只有两个 server 组成的集群为例，当 leader S1 接受到新配置之后，其不应该立马切换为 follower，而是应该将该配置复制到 follower S2，然后再切换。S2 也不能成为 leader 直到它接收到 S1 的新配置。

![removal](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/removal.png)

从 leader 的身份成功切换，到接受新配置的 server 当选为 leader 的这段短暂不可用期，**应是一个集群可以承受的**。
#### 扰动性选举
当 leader 创建新配置的 log entry 后，其他**没有接收到新配置的 server 不会再接收到 leader 的心跳包**。由于没有接收到新的配置项，所以这些 server 是不知道自己已经被移出集群了，它们反而会产生 election timeout 并开启选举，并向其他 server 发送带有最新任期数的`RequestVote RPC`请求，现任 leader 在接收到该请求后会沦为 follower。最后，新的 leader 虽然还是从拥有新配置的那些 server 中选举出来，但该 leader server 可能已经不是原来的 leader server 了。这个过程会伴随着旧配置的那些 server 不断 timeout 然后不断的进行重新选举，造成集群整体的可用性降低。
##### 预投票阶段
Raft 尝试引入一个**预投票阶段**来解决上述问题，即 candidate 会首先向其他 server 询问，自己的 log 是否足够的新，以获取足够多的选票。只有 candidate 认为自己能够获取大多数 server 的投票后，才会增加任期数并开始一轮正常的选举。

Etcd 于 v3.4 引入预投票阶段作为实验性 feature，并于 v3.5 正式成为默认 feature。在 server 开始进行选举时，会首先切换为 PreCandidate 角色发起预投票：
```go
// raft/raft.go

func (r *raft) campaign(t CampaignType) {
	// ...
	var term uint64
	var voteMsg pb.MessageType
	if t == campaignPreElection {
		r.becomePreCandidate()
		voteMsg = pb.MsgPreVote
		term = r.Term + 1    // 它虽然以下个任期数发送，但是不是通过增加 r.Term 的方式来的
	} else {
		r.becomeCandidate()  // ===> r.reset(r.Term + 1)，成为正式的 candidate 后才是通过增加 r.Term 的方式来的
		voteMsg = pb.MsgVote
		term = r.Term
	}

        // 对于单节点的集群，成为 candidate 之后可直接成为 leader
	if _, _, res := r.poll(r.id, voteRespMsgType(voteMsg), true); res == quorum.VoteWon {
		if t == campaignPreElection {
			r.campaign(campaignElection)
		} else {
			r.becomeLeader()
		}
		return
	}
	// ...
	for _, id := range ids {
		if id == r.id {
			continue
		}
		var ctx []byte
		if t == campaignTransfer {  // 记录投票原因为 leader 转移
			ctx = []byte(t)
		}
                // 向所有其他除了自己之外的 server 发起投票请求
		r.send(pb.Message{Term: term, To: id, Type: voteMsg, Index: r.raftLog.lastIndex(), LogTerm: r.raftLog.lastTerm(), Context: ctx})
	}
}
```
针对预投票请求，每个 server 在投票前都会进行各种检查，最主要的就是保证 candidate 的日志足够新：
```go
// raft/raft.go

func (r *raft) Step(m pb.Message) error {
	// ...

	switch m.Type {
	// ...
        // 针对正式投票与预投票消息
	case pb.MsgVote, pb.MsgPreVote:
		// 什么样的情况下才可以进行投票？
		canVote := r.Vote == m.From ||  // 收到了已票选对象的重复投票请求
			(r.Vote == None && r.lead == None) ||  // 没有投过票，并且当前任期中也不存在 leader
			(m.Type == pb.MsgPreVote && m.Term > r.Term)  // 任期数比当前任期数大的预投票请求
		// 无论哪种投票请求类型，都需要保证 candidate 的 log 足够的新
		if canVote && r.raftLog.isUpToDate(m.Index, m.LogTerm) {
			r.send(pb.Message{To: m.From, Term: m.Term, Type: voteRespMsgType(m.Type)})  // 使用新任期
			if m.Type == pb.MsgVote {
				// election timeout 计时清零，并记录票选对象
				r.electionElapsed = 0
				r.Vote = m.From
			}
		} else {
			// 针对投票请求，返回拒绝投票响应
			r.send(pb.Message{To: m.From, Term: r.Term, Type: voteRespMsgType(m.Type), Reject: true})  // 任期不变
		}

	// ...
}
```
**但预投票并不能完全解决这个问题**。如下图所示，倘若在 leader S4 复制并提交新配置 entry 之前，S1～S3 接收不到心跳包了，S1 有可能 timeout，并将含有最新任期数的投票请求发给 S4，迫使 S4 沦为 follower。此时，对于 S1 来说，预投票失效，因为它的 log 在集群大多数节点中也为新的。

![pre-vote](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/pre-vote.png)
##### 选举条件
针对上述问题，Raft 建议的做法是：如果一个 leader 可以在一个集群中发送心跳包，则不允许 leader 及其 followers 采纳拥有更高任期的投票请求。这种做法不仅可以避免由旧配置 server 引发的扰动性选举问题，而且还不会影响到正常的选举流程。

同样在 Etcd 的实现中，所有 server 对于投票或预投票的消息请求，都会先判断自身是否在一个 leader 的任期并且还在接受 leader 的心跳包：
```go
// raft/raft.go

func (r *raft) Step(m pb.Message) error {
	switch {
	case m.Term == 0:
		// local message
	case m.Term > r.Term:
		if m.Type == pb.MsgVote || m.Type == pb.MsgPreVote {
			force := bytes.Equal(m.Context, []byte(campaignTransfer))  // 投票原因是否为 leader 转移
			inLease := r.checkQuorum && r.lead != None && r.electionElapsed < r.electionTimeout  // 没有产生 election timeout，说明在正常接收/发送心跳
			if !force && inLease {
                        // 对于非 leader 转移并且在一个正常的任期内接收心跳，此时直接返回，不进行投票
				return nil
			}
		}
        // ...
    }
    // ...
}
```
## 多成员变更
多成员的变更虽然可以处理为多次单成员的变更，但在实际的场景中，这种做法可能并不实用。

与单成员变更不同的是，在多成员变更中，集群节点**不可能立即从旧配置切换到新的配置**，因为有关新、旧配置 overlap 的约束已经不成立了。这就意味着，整个集群肯定存在某个时刻，被新、旧配置分离（disjoint）为了两个 majorities。比如下图 Server 1～2 属于一个 majority，Server 3～5 属于另一个 majority。

![two-major](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/two-major.png)
### 联合一致性
为了保证任意成员/配置变更的安全性，Raft 会首先将集群的配置切换为一种过渡配置，即联合一致性（joint consensus）。一旦联合一致性被提交（committed），集群才会过度到新配置。联合一致性共同包含了新、旧两种配置：

- 这种联合配置的 log entries 会被复制到 server 中
- 任意一个包含这种配置的 server 都有可能被选举为 leader
- 选举和 entry 的提交需要来自两个不同 majorities 的投票。例如，当一个集群的节点个数由 3 个增加到 9 个时，旧配置中 3 个 servers 的 2 个，以及新配置中 9 个 servers 的 5 个，都需要获取同意

![joint-consensus](https://raw.githubusercontent.com/shawnh2/shawnh2.github.io/master/_posts/img/2023-06-25/joint-consensus.png)

当一个 leader 接收到需要将旧配置变更为新配置的请求时，它会将联合配置作为一个 log entry 存储起来，并复制给 followers。与单节点变更的日志复制相同，follower 在接收到联合配置后便立即生效。如果此时 leader 挂了，新选举出的 leader **可能也只可能属于旧配置或者联合配置**（这取决于它是否接收到了联合配置）。一旦联合配置被提交，leader 便开始创建新配置的 log entry 并复制到集群，server 接收到的新配置也是立马生效。当新配置被提交之后，那些不属于新配置的 server 会被关停。

**这种配置变更方式属于两阶段提交**。如上图所示，集群中**不存在**任意一个时刻，新配置和旧配置同时参与决策。

在 Etcd 中，其实**并没有实现**多成员配置变更的这种情况，它还是每次只变更一个成员。与 Raft 不同的是，Etcd 中成员配置变更的生效时刻**不是在**配置的 entry 加入到 log 之后，而是在该 entry 被提交之后。

## Reference

1. [https://github.com/ongardie/dissertation/blob/master/stanford.pdf](https://github.com/ongardie/dissertation/blob/master/stanford.pdf)
2. [https://github.com/etcd-io/etcd/blob/release-3.4/Documentation/learning/design-learner.md](https://github.com/etcd-io/etcd/blob/release-3.4/Documentation/learning/design-learner.md)
3. [https://github.com/etcd-io/etcd/blob/release-3.4/raft/README.md](https://github.com/etcd-io/etcd/blob/release-3.4/raft/README.md)
4. [https://github.com/etcd-io/etcd/blob/release-3.4/raft/design.md](https://github.com/etcd-io/etcd/blob/release-3.4/raft/design.md)
5. [https://kubernetes.io/blog/2019/08/30/announcing-etcd-3-4/](https://kubernetes.io/blog/2019/08/30/announcing-etcd-3-4/)
