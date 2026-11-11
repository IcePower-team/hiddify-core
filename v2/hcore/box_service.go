// Package hcore — personal fork (IcePower-team): local BoxService replaces
// the libbox BoxService removed in sing-box v1.15.
package hcore

import (
	"context"
	"os"
	"time"

	B "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
	runtimeDebug "runtime/debug"
)

// BoxService is hcore's own replacement for the libbox.BoxService that
// sing-box removed in the v1.13/v1.15 API migration: it bundles the box
// instance with its context, cancel func, url-test history storage and
// pause manager, exposing the small surface hcore uses.
type BoxService struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	instance              *B.Box
	pauseManager          pause.Manager
	urlTestHistoryStorage *urltest.HistoryStorage
}

func newBoxService(ctx context.Context, cancel context.CancelFunc, instance *B.Box, pauseManager pause.Manager, urlTestHistoryStorage *urltest.HistoryStorage) *BoxService {
	return &BoxService{
		ctx:                   ctx,
		cancel:                cancel,
		instance:              instance,
		pauseManager:          pauseManager,
		urlTestHistoryStorage: urlTestHistoryStorage,
	}
}

func (s *BoxService) UrlTestHistory() *urltest.HistoryStorage {
	return s.urlTestHistoryStorage
}

func (s *BoxService) Context() context.Context {
	return s.ctx
}

func (s *BoxService) GetInstance() *B.Box {
	return s.instance
}

func (s *BoxService) Start() error {
	return s.instance.Start()
}

func (s *BoxService) Close() error {
	s.cancel()
	s.urlTestHistoryStorage.Close()
	var err error
	done := make(chan struct{})
	go func() {
		err = s.instance.Close()
		close(done)
	}()
	select {
	case <-done:
		return err
	case <-time.After(C.FatalStopTimeout):
		os.Exit(1)
		return nil
	}
}

// newHService replicates the removed libbox.NewHService: it builds the
// service context (filemanager paths, url-test history storage, platform
// interface) and creates the box. The platform interface now travels in
// the context, since box.Options no longer carries it.
func newHService(options option.Options, platformInterface libbox.PlatformInterface) (*BoxService, error) {
	runtimeDebug.FreeOSMemory()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = filemanager.WithDefault(ctx, sWorkingPath, sTempPath, sUserID, sGroupID)
	urlTestHistoryStorage := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
	if platformInterface != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, libbox.WrapPlatformInterface(platformInterface))
	}
	instance, err := B.New(B.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: &LogInterface{},
	})
	if err != nil {
		cancel()
		return nil, E.Cause(err, "create service")
	}
	runtimeDebug.FreeOSMemory()
	return newBoxService(
		ctx,
		cancel,
		instance,
		service.FromContext[pause.Manager](ctx),
		urlTestHistoryStorage,
	), nil
}
