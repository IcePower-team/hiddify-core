package hcore

import (
	"github.com/hiddify/hiddify-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
)

// hiddifyMainServiceManager runs the hiddify service extensions around the
// main box service. It is registered as a lifecycle service, so Start runs
// at the post-start stage (the old AddPostService hook) and Close is
// registered as a scope cleanup.
type hiddifyMainServiceManager struct{}

var _ adapter.LifecycleService = (*hiddifyMainServiceManager)(nil)

func (h *hiddifyMainServiceManager) Name() string {
	return "hiddifyMainServiceManager"
}

func (h *hiddifyMainServiceManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	scope.Add(func() error {
		return service_manager.OnMainServiceClose()
	})
	return service_manager.OnMainServiceStart()
}
