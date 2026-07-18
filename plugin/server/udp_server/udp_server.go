package udp_server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	PluginType       = "udp_server"
	asyncRefreshMark = 1 << 60

	fastRefreshEventBaseSize               = 280
	fastRefreshEventV1Size                 = 296
	fastRefreshEventMagicOffset            = 280
	fastRefreshEventHitCountOffset         = 284
	fastRefreshEventLastHitNSOffset        = 288
	fastRefreshEventMagicV1         uint32 = 0x31484346 // "FCH1" in little endian.
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Entry       string         `yaml:"entry"`
	Listen      string         `yaml:"listen"`
	EnableAudit bool           `yaml:"enable_audit"`
	FastCache   *FastCacheArgs `yaml:"fast_cache"`
}

func (a *Args) init() (resolvedFastCacheMode, error) {
	utils.SetDefaultString(&a.Listen, "127.0.0.1:53")
	return normalizeFastCacheArgs(a.FastCache)
}

type UdpServer struct {
	args      *Args
	c         net.PacketConn
	cancel    context.CancelFunc
	fastCache *fastCache
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func (s *UdpServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.fastCache != nil {
			s.fastCache.stop()
		}
		if s.c != nil {
			err = s.c.Close()
		}
		s.wg.Wait()
		if s.fastCache != nil {
			s.fastCache.Close()
		}
	})
	return err
}

type SwitchPlugin interface{ GetValue() string }
type DomainMapperPlugin interface {
	FastMatch(qname string) ([]uint8, string, bool)
	GetRunBit() uint8
}
type IPSetPlugin interface{ Match(addr netip.Addr) bool }

type fastHandler struct {
	next             server.Handler
	fc               *fastCache
	sw               SwitchPlugin
	legacySwitchGate bool
	releasePayload   func(*[]byte)
}

func (h *fastHandler) Handle(ctx context.Context, q *dns.Msg, meta server.QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	meta.ClientAddr = meta.ClientAddr.Unmap()
	payload := h.next.Handle(ctx, q, meta, pack)

	if (meta.PreFastFlags & asyncRefreshMark) != 0 {
		if payload != nil && q.Opcode == dns.OpcodeQuery && len(q.Question) > 0 {
			h.fc.Store(*payload, true)
		}
		if payload != nil && h.releasePayload != nil {
			h.releasePayload(payload)
		}
		return nil
	}

	if h.legacySwitchGate && h.sw != nil && h.sw.GetValue() != "A" {
		return payload
	}

	if payload != nil && (meta.PreFastFlags&(1<<30)) == 0 && q.Opcode == dns.OpcodeQuery && len(q.Question) > 0 {
		h.fc.Store(*payload, false)
	}
	return payload
}

const (
	fastRefreshWorkers = 4
	fastRefreshQueue   = 1024
	fastRefreshTimeout = 2 * time.Second
	fastRingReopen     = 3 * time.Second
)

type fastRefreshEvent struct {
	msg  *dns.Msg
	meta server.QueryMeta
}

func decodeFastRefreshEvent(sample []byte) (fastRefreshEvent, bool) {
	if len(sample) < fastRefreshEventBaseSize {
		return fastRefreshEvent{}, false
	}
	isV6 := binary.LittleEndian.Uint16(sample[0:2])
	dnsLen := int(binary.LittleEndian.Uint16(sample[4:6]))
	if dnsLen == 0 || dnsLen > 256 || 24+dnsLen > len(sample) {
		return fastRefreshEvent{}, false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(sample[24 : 24+dnsLen]); err != nil {
		return fastRefreshEvent{}, false
	}

	var clientIP netip.Addr
	switch isV6 {
	case 0:
		clientIP = netip.AddrFrom4(*(*[4]byte)(sample[8:12]))
	case 1:
		clientIP = netip.AddrFrom16(*(*[16]byte)(sample[8:24]))
	default:
		return fastRefreshEvent{}, false
	}
	hits := uint32(1)
	// The currently shipped eBPF objects emit the historical 280-byte event and
	// can only prove that at least one client query triggered this refresh. A
	// future source-built object may append the v1 telemetry trailer without
	// changing the compatible prefix. Until then kernel mode reports weight 1.
	if len(sample) >= fastRefreshEventV1Size &&
		binary.LittleEndian.Uint32(sample[fastRefreshEventMagicOffset:fastRefreshEventHitCountOffset]) == fastRefreshEventMagicV1 {
		if reported := binary.LittleEndian.Uint32(sample[fastRefreshEventHitCountOffset:fastRefreshEventLastHitNSOffset]); reported > 0 {
			hits = reported
		}
	}
	return fastRefreshEvent{
		msg: msg,
		meta: server.QueryMeta{
			ClientAddr:    clientIP,
			FromUDP:       true,
			PreFastFlags:  asyncRefreshMark,
			FastCacheHits: hits,
		},
	}, true
}

func startFastRefreshWorker(ctx context.Context, h *fastHandler, queue <-chan fastRefreshEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case event := <-queue:
			refreshCtx, cancel := context.WithTimeout(ctx, fastRefreshTimeout)
			payload := h.Handle(refreshCtx, event.msg, event.meta, pool.PackBuffer)
			cancel()
			// asyncRefreshMark normally makes fastHandler consume the payload and
			// return nil. Keep this defensive release for alternate handlers.
			if payload != nil {
				pool.ReleaseBuf(payload)
			}
		}
	}
}

func startRingbufListener(ctx context.Context, rd *ringbuf.Reader, queue chan<- fastRefreshEvent) error {
	started := time.Now()
	var rec ringbuf.Record
	for {
		rd.SetDeadline(time.Now().Add(time.Second))
		err := rd.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Periodically reopen the pinned map. This makes the consumer move
				// to a new map generation after nft_add replaces stale bpffs pins.
				if time.Since(started) >= fastRingReopen {
					return nil
				}
				continue
			}
			return err
		}
		event, ok := decodeFastRefreshEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case queue <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func Init(bp *coremain.BP, args any) (any, error) {
	return StartServer(bp, args.(*Args))
}

func StartServer(bp *coremain.BP, args *Args) (*UdpServer, error) {
	if args == nil {
		return nil, fmt.Errorf("udp_server args must not be nil")
	}
	mode, err := args.init()
	if err != nil {
		return nil, err
	}
	dh, err := server_utils.NewHandler(bp, args.Entry, args.EnableAudit)
	if err != nil {
		return nil, fmt.Errorf("failed to init dns handler, %w", err)
	}

	socketOpt := server_utils.ListenerSocketOpts{
		SO_REUSEPORT: true,
		SO_RCVBUF:    2 * 1024 * 1024,
	}
	lc := net.ListenConfig{Control: server_utils.ListenerControl(socketOpt)}
	c, err := lc.ListenPacket(context.Background(), "udp", args.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket, %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = c.Close()
		}
	}()

	isEbpfPort := false
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if udpAddr.Port == 53 {
			isEbpfPort = true
		}
	}

	if mode.legacy && !isEbpfPort {
		mode = resolvedFastCacheMode{}
	}
	if mode.kernel && !isEbpfPort {
		return nil, fmt.Errorf("fast_cache kernel mode requires UDP port 53")
	}
	if mode.kernel && runtime.GOOS != "linux" {
		if !mode.legacy {
			return nil, fmt.Errorf("fast_cache kernel mode is only supported on Linux")
		}
		mode.kernel = false
	}

	var sw15 SwitchPlugin
	if p := bp.M().GetPlugin("switch15"); p != nil {
		sw15, _ = p.(SwitchPlugin)
	}
	if mode.legacy && sw15 != nil {
		mode.userspace = true
	}

	runtimeCtx, cancel := context.WithCancel(context.Background())
	s := &UdpServer{args: args, c: c, cancel: cancel}
	var wrappedHandler server.Handler = dh
	var wrappedFastHandler *fastHandler
	if mode.kernel || mode.userspace || mode.legacy {
		fc, err := newFastCache(mode, bp.L())
		if err != nil {
			cancel()
			return nil, err
		}
		s.fastCache = fc
		wrappedFastHandler = &fastHandler{
			next:             dh,
			fc:               fc,
			sw:               sw15,
			legacySwitchGate: mode.legacy && sw15 != nil,
			releasePayload:   pool.ReleaseBuf,
		}
		wrappedHandler = wrappedFastHandler
	}

	// Keep the policy pre-fast stage independent from cache storage. switch15
	// users retain their early marks/reject behavior even in off/kernel mode.
	var fastBypass func(int, []byte, netip.AddrPort) (int, int, uint64, string, uint32)
	if isEbpfPort || (mode.userspace && !mode.legacy) {
		fastBypass = buildFastBypass(
			bp,
			s.fastCache,
			c.(*net.UDPConn),
			mode.userspace && !mode.legacy,
			mode.legacy,
		)
	}

	if mode.kernel && wrappedFastHandler != nil {
		queue := make(chan fastRefreshEvent, fastRefreshQueue)
		for i := 0; i < fastRefreshWorkers; i++ {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				startFastRefreshWorker(runtimeCtx, wrappedFastHandler, queue)
			}()
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			runFastRingbuf(runtimeCtx, s.fastCache, queue)
		}()
	}

	resolvedMode := "off"
	switch {
	case mode.kernel && mode.userspace:
		resolvedMode = "both"
	case mode.kernel:
		resolvedMode = "kernel"
	case mode.userspace:
		resolvedMode = "userspace"
	}
	if mode.legacy {
		resolvedMode = "legacy/" + resolvedMode
	}
	bp.L().Info("udp server fast cache configured",
		zap.String("mode", resolvedMode),
		zap.Int("userspace_capacity", func() int {
			if s.fastCache == nil {
				return 0
			}
			return s.fastCache.localCapacity()
		}()),
		zap.Stringer("addr", c.LocalAddr()))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer c.Close()
		err := server.ServeUDP(c.(*net.UDPConn), wrappedHandler, server.UDPServerOpts{
			Logger:                  bp.L(),
			FastBypassWithTelemetry: fastBypass,
		})
		bp.M().GetSafeClose().SendCloseSignal(err)
	}()
	closeOnError = false
	return s, nil
}

func waitFastCacheRetry(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func runFastRingbuf(ctx context.Context, fc *fastCache, queue chan<- fastRefreshEvent) {
	var lastID ebpf.MapID
	var haveLastID bool
	for ctx.Err() == nil {
		rm, err := ebpf.LoadPinnedMap("/sys/fs/bpf/mosdns_ringbuf", nil)
		if err != nil {
			if !waitFastCacheRetry(ctx, fastCacheKernelRetryDelay) {
				return
			}
			continue
		}
		if rm.Type() != ebpf.RingBuf {
			_ = rm.Close()
			if !waitFastCacheRetry(ctx, fastCacheKernelRetryDelay) {
				return
			}
			continue
		}
		if info, infoErr := rm.Info(); infoErr == nil {
			if id, ok := info.ID(); ok && (!haveLastID || id != lastID) {
				lastID, haveLastID = id, true
				fc.requestKernelReload()
			}
		}
		rd, err := ringbuf.NewReader(rm)
		if err != nil {
			_ = rm.Close()
			if !waitFastCacheRetry(ctx, fastCacheKernelRetryDelay) {
				return
			}
			continue
		}
		listenErr := startRingbufListener(ctx, rd, queue)
		_ = rd.Close()
		_ = rm.Close()
		if listenErr != nil && ctx.Err() == nil {
			if !waitFastCacheRetry(ctx, fastCacheKernelRetryDelay) {
				return
			}
		}
	}
}

func buildFastBypass(
	bp *coremain.BP,
	fc *fastCache,
	conn *net.UDPConn,
	explicitUserspace bool,
	legacy bool,
) func(int, []byte, netip.AddrPort) (int, int, uint64, string, uint32) {
	var sw15 SwitchPlugin
	var dm DomainMapperPlugin
	var ipSet IPSetPlugin
	dependenciesResolved := false

	return func(reqLen int, buf []byte, remoteAddr netip.AddrPort) (int, int, uint64, string, uint32) {
		// Plugins are loaded in configuration order while the UDP listener is
		// already live. Retry missing dependencies instead of permanently caching
		// nil from the first packet.
		if !dependenciesResolved {
			if sw15 == nil {
				if p := bp.M().GetPlugin("switch15"); p != nil {
					sw15, _ = p.(SwitchPlugin)
				}
			}
			if dm == nil {
				if p := bp.M().GetPlugin("unified_matcher1"); p != nil {
					dm, _ = p.(DomainMapperPlugin)
				}
			}
			if ipSet == nil {
				if p := bp.M().GetPlugin("client_ip"); p != nil {
					ipSet, _ = p.(IPSetPlugin)
				}
			}
			dependenciesResolved = bp.M().PluginsLoaded()
		}

		switchActive := sw15 != nil && (query_context.GlobalSwitchMask.Load()&(1<<46)) != 0
		lookupUserspace := explicitUserspace
		if legacy {
			if !switchActive {
				return server.FastActionContinue, 0, 0, "", 0
			}
			if fc != nil && !fc.userspaceEnabled() {
				// The legacy table is about 32 MiB at its historical size. Ask the
				// cache maintenance goroutine to allocate it so the UDP read loop
				// never pauses for a large allocation.
				fc.requestUserspaceEnable()
			}
			lookupUserspace = fc != nil && fc.userspaceEnabled()
		} else if !lookupUserspace && !switchActive {
			return server.FastActionContinue, 0, 0, "", 0
		}

		var marks uint64
		var dset string
		if switchActive {
			action, respLen, policyMarks, policyDset, allowCache := applyFastPolicy(
				reqLen,
				buf,
				remoteAddr,
				query_context.GlobalSwitchMask.Load(),
				dm,
				ipSet,
			)
			marks, dset = policyMarks, policyDset
			if action == server.FastActionReply || !allowCache {
				return action, respLen, marks, dset, 0
			}
		}

		if !lookupUserspace || fc == nil {
			return server.FastActionContinue, 0, marks, dset, 0
		}
		qRawBytes, ok := fastQuestionWire(buf[:reqLen])
		if !ok {
			return server.FastActionContinue, 0, marks, dset, 0
		}
		hKey := calcFNV1a(qRawBytes)
		ptr := fc.lookupLocal(hKey, qRawBytes)

		if ptr != nil {
			ptr.activity.addHit()
			now := fc.deps.now().Unix()
			expireTime := atomic.LoadInt64(&ptr.expire)
			if now > expireTime {
				isStuck := now > expireTime+10
				if isStuck {
					atomic.CompareAndSwapUint32(&ptr.updating, 1, 0)
				}
				if atomic.CompareAndSwapUint32(&ptr.updating, 0, 1) {
					atomic.StoreInt64(&ptr.expire, now+fastCacheInternalTTL)

					bakedStale := append([]byte(nil), ptr.resp...)
					bakedStale[0], bakedStale[1] = buf[0], buf[1]
					copy(bakedStale[12:12+len(qRawBytes)], qRawBytes)

					_, _ = conn.WriteToUDPAddrPort(bakedStale, remoteAddr)

					hits := ptr.activity.takeHits()
					if hits == 0 {
						hits = 1
					}
					return server.FastActionContinue, 0, marks | asyncRefreshMark, dset, hits
				}
			}
			respLen := len(ptr.resp)
			txid0, txid1 := buf[0], buf[1]
			copy(buf, ptr.resp)
			buf[0], buf[1] = txid0, txid1
			copy(buf[12:12+len(qRawBytes)], qRawBytes)
			return server.FastActionReply, respLen, 0, "", 0
		}
		return server.FastActionContinue, 0, marks, dset, 0
	}
}

func applyFastPolicy(
	reqLen int,
	buf []byte,
	remoteAddr netip.AddrPort,
	marks uint64,
	dm DomainMapperPlugin,
	ipSet IPSetPlugin,
) (action int, respLen int, outMarks uint64, dset string, allowCache bool) {
	if reqLen < 12 {
		return server.FastActionContinue, 0, 0, "", false
	}

	qtypeOff := 12
	for qtypeOff < reqLen {
		l := int(buf[qtypeOff])
		if l == 0 {
			qtypeOff++
			break
		}
		if l&0xC0 == 0xC0 {
			qtypeOff += 2
			break
		}
		qtypeOff += l + 1
	}
	if qtypeOff+2 > reqLen {
		return server.FastActionContinue, 0, 0, "", false
	}
	qtype := binary.BigEndian.Uint16(buf[qtypeOff : qtypeOff+2])

	if (qtype == 6 || qtype == 12 || qtype == 65) && (marks&(1<<36)) != 0 {
		return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 0), 0, "", false
	}
	if qtype == 28 && (marks&(1<<37)) != 0 {
		return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 0), 0, "", false
	}

	offset := 12
	var nameBuf [256]byte
	nameLen := 0
	for offset < reqLen {
		l := int(buf[offset])
		if l == 0 {
			offset++
			if nameLen == 0 {
				nameBuf[0] = '.'
				nameLen = 1
			}
			break
		}
		if l&0xC0 == 0xC0 {
			return server.FastActionContinue, 0, 0, "", false
		}
		offset++
		if offset+l > reqLen || nameLen+l+1 > len(nameBuf) {
			return server.FastActionContinue, 0, 0, "", false
		}
		copy(nameBuf[nameLen:], buf[offset:offset+l])
		nameLen += l
		nameBuf[nameLen] = '.'
		nameLen++
		offset += l
	}

	if dm != nil {
		marks |= 1 << dm.GetRunBit()
		if mList, dsName, match := dm.FastMatch(string(nameBuf[:nameLen])); match {
			for _, v := range mList {
				if v < 64 {
					marks |= 1 << v
				}
			}
			dset = dsName
		}
	}

	if (marks & (1 << 32)) != 0 {
		if (marks & (1 << 1)) != 0 {
			return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 3), 0, "", false
		}
		if (marks&(1<<2)) != 0 && qtype == 1 {
			return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 0), 0, "", false
		}
		if (marks&(1<<3)) != 0 && qtype == 28 {
			return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 0), 0, "", false
		}
	}
	if (marks&(1<<38)) != 0 && (marks&(1<<5)) != 0 {
		return server.FastActionReply, makeReject(reqLen, buf, qtypeOff+4, 3), 0, "", false
	}

	ipMatch := false
	if ipSet != nil {
		ipMatch = ipSet.Match(remoteAddr.Addr().Unmap())
		marks |= 1 << 48
	}

	sw2A := (marks & (1 << 33)) != 0
	sw2B := !sw2A
	sw12A := (marks & (1 << 43)) != 0
	sw12B := !sw12A
	if (sw2A && sw12B && !ipMatch) || (sw2B && sw12A && ipMatch) {
		marks |= 1 << 30
	}

	if (marks&(1<<6)) != 0 || (marks&(1<<30)) != 0 {
		return server.FastActionContinue, 0, marks, dset, false
	}
	return server.FastActionContinue, 0, marks, dset, true
}

func makeReject(reqLen int, buf []byte, offset int, rcode byte) int {
	if offset > reqLen {
		offset = reqLen
	}
	buf[2] |= 0x80
	buf[3] |= 0x80
	buf[3] = (buf[3] & 0xF0) | (rcode & 0x0F)
	buf[6], buf[7] = 0, 0
	buf[8], buf[9] = 0, 0
	buf[10], buf[11] = 0, 0
	return offset
}
