// Copyright 2022-2022 The jdh99 Authors. All rights reserved.
// 接口
// Authors: jdh99 <jdh821@163.com>

package connect

import (
	"github.com/jdhxyy/knock"
	"github.com/jdhxyy/lagan"
	"github.com/jdhxyy/standardlayer"
	"github.com/jdhxyy/utz"
)

const (
	tag = "connect"
)

var gLocalIA uint32 = utz.IAInvalid
var gCoreIP uint32
var gCorePort uint16
var gCoreIA uint32
var gPipe int

// Load 模块载入
func Load(ia uint32, coreIA uint32, coreIP uint32, corePort uint16, pipe int) {
	gLocalIA = ia
	gCoreIA = coreIA
	gCoreIP = coreIP
	gCorePort = corePort
	gPipe = pipe

	standardlayer.RegisterRxObserver(dealSlRx)
}

// dealSlRx 处理标准层回调函数
func dealSlRx(data []uint8, standardHeader *utz.StandardHeader, ip uint32, port uint16) {
	if gLocalIA == utz.IAInvalid || standardHeader.DstIA != gLocalIA {
		return
	}

	var agentHeader *utz.AgentHeader = nil
	offset := 0
	nextHead := standardHeader.NextHead
	if standardHeader.NextHead == utz.HeaderAgent {
		agentHeader, offset = utz.BytesToAgentHeader(data)
		if agentHeader == nil || offset == 0 {
			lagan.Warn(tag, "bytes to agent header failed.ia:0x%08x addr:0x%08x:%d", standardHeader.SrcIA, ip,
				port)
			return
		}
		nextHead = agentHeader.NextHead
		rtAdd(standardHeader.SrcIA, agentHeader.IA)
	}

	if nextHead != utz.HeaderCcp && nextHead != utz.HeaderCmp && nextHead != utz.HeaderDup {
		return
	}

	cmp := utz.CcpFrameToBytes(data[offset:])
	if cmp == nil || len(cmp) == 0 {
		lagan.Warn(tag, "ccp frame to bytes failed.ia:0x%x addr:0x%08x:%d", standardHeader.SrcIA, ip, port)
		return
	}
	if len(cmp) == 0 {
		lagan.Warn(tag, "data len is wrong.ia:0x%x addr:0x%08x:%d", standardHeader.SrcIA, ip, port)
		return
	}

	resp := knock.Call(uint16(nextHead), uint16(cmp[0]), cmp[1:], standardHeader.SrcIA, ip, port)
	if resp == nil {
		return
	}

	// 加命令字回复
	respReal := make([]uint8, 1)
	respReal[0] = utz.GetAckCmd(cmp[0])
	respReal = append(respReal, resp...)
	respReal = utz.BytesToCcpFrame(respReal)

	var ackHeader utz.StandardHeader
	ackHeader.Version = utz.ProtocolVersion
	ackHeader.NextHead = nextHead
	ackHeader.SrcIA = gLocalIA
	ackHeader.DstIA = standardHeader.SrcIA

	if agentHeader != nil {
		// 如果发过来有代理头部,则回复需要加路由头部
		var routeHeader utz.RouteHeader
		routeHeader.NextHead = ackHeader.NextHead
		routeHeader.IA = agentHeader.IA

		ackHeader.NextHead = utz.HeaderRoute
		respReal = append(routeHeader.Bytes(), respReal...)
	}

	// 加命令字回复
	standardlayer.Send(respReal, &ackHeader, ip, port)
}
