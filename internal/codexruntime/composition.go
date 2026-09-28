package codexruntime

import (
	"context"
	"time"

	"openduck/internal/harness"
)

// LifecycleController is the exact Controller mutation surface required for a
// worker. It intentionally has no preview, owner-decision, grant or effect
// method. The caller still has to construct the WorkOrder from a frozen spec.
type LifecycleController interface {
	Dispatch(context.Context, string, uint64, harness.WorkOrder, harness.WorkerRuntimeAttestation, harness.WorkerDispatchBinding) (harness.TaskRecord, error)
	StartWork(context.Context, string, uint64) (harness.TaskRecord, error)
	SubmitWorkerResult(context.Context, string, uint64, harness.WorkerResult, time.Time) (harness.TaskRecord, error)
}

// DispatchAndExecute makes the required order of authority explicit:
//
//  1. launch/observe the isolated process;
//  2. bind its attestation to a frozen WorkOrder in Controller;
//  3. transition to WORK_RUNNING;
//  4. run the one bounded turn and submit only the WorkerResult.
//
// Any failure leaves a visible Controller lifecycle state and never invents
// evidence, owner approval, or external effect.
func DispatchAndExecute(ctx context.Context, controller LifecycleController, runner *Runner, taskID string, version uint64, order harness.WorkOrder) (harness.TaskRecord, Result, error) {
	if controller == nil || runner == nil || taskID == "" || version == 0 || order.TaskID != taskID {
		return harness.TaskRecord{}, Result{}, ErrUnsafeRuntime
	}
	session, err := runner.Prepare(ctx, order)
	if err != nil {
		return harness.TaskRecord{}, Result{}, err
	}
	defer session.Close()
	dispatched, err := controller.Dispatch(ctx, taskID, version, order, session.Attestation(), session.Binding())
	if err != nil {
		return harness.TaskRecord{}, Result{}, err
	}
	running, err := controller.StartWork(ctx, taskID, dispatched.Version)
	if err != nil {
		return harness.TaskRecord{}, Result{}, err
	}
	worker, err := session.Run(ctx)
	if err != nil {
		return running, Result{}, err
	}
	completed, err := controller.SubmitWorkerResult(ctx, taskID, running.Version, worker, time.Now().UTC())
	if err != nil {
		return running, Result{}, err
	}
	return completed, Result{WorkerResult: worker, Attestation: session.Attestation(), Binding: session.Binding()}, nil
}
