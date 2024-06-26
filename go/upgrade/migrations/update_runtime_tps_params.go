package migrations

import (
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
    registry "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
    //governance "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	common "github.com/oasisprotocol/oasis-core/go/common"
)

const (
	// UpgradeHandler is the name of the upgrade that sets the
	// runtime tps parameter.
	UpgradeHandler = "update-runtime-tps-params"
)

var _ Handler = (*allowEntityRegHandler)(nil)

type allowEntityRegHandler struct{}

func (th *allowEntityRegHandler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (th *allowEntityRegHandler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	switch abciCtx.Mode() {
	case abciAPI.ContextBeginBlock:
		// Nothing to do during begin block.
	case abciAPI.ContextEndBlock:
		// Update a consensus parameter during EndBlock.

        // update governance parameters
        /*
		govState := governance.NewMutableState(abciCtx.State())

		params, err := govState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load staking consensus parameters: %w", err)
		}

        params.VotingPeriod = 12
		params.UpgradeMinEpochDiff = 24

		if err = govState.SetConsensusParameters(abciCtx, params); err != nil {
			return fmt.Errorf("failed to update registry consensus parameters: %w", err)
		}
        */

        // update registry parameters

		regState := registry.NewMutableState(abciCtx.State())

        /*
		params, err := regState.ConsensusParameters(abciCtx)
		if err != nil {
			return fmt.Errorf("unable to load staking consensus parameters: %w", err)
		}

		params.DisableEntityRegistration = false

		if err = regState.SetConsensusParameters(abciCtx, params); err != nil {
			return fmt.Errorf("failed to update registry consensus parameters: %w", err)
		}
        */

        // update runtime parameters

        var runtimeId common.Namespace
        runtimeId.UnmarshalHex("000000000000000000000000000000000000000000000000324f850f9a308d98")

        suspended := false
        runtime, err := regState.Runtime(abciCtx, runtimeId)
		if err != nil {
            suspended = true
            runtime, err = regState.SuspendedRuntime(abciCtx, runtimeId)
		}

		if err != nil {
            return fmt.Errorf("unable to load runtime: %w", err)
        }

        runtime.TxnScheduler.MaxBatchSize = 10000
        runtime.TxnScheduler.MaxBatchSizeBytes = 22020096
        runtime.TxnScheduler.ProposerTimeout = 12

        if err = regState.SetRuntime(abciCtx, runtime, suspended); err != nil {
			return fmt.Errorf("failed to update registry runtime descriptor: %w", err)
        }

	default:
		return fmt.Errorf("upgrade handler called in unexpected context: %s", abciCtx.Mode())
	}
	return nil
}

func init() {
	Register(UpgradeHandler, &allowEntityRegHandler{})
}
