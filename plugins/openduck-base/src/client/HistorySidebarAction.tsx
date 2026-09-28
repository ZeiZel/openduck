import React, { useState } from 'react'
import { Button, Modal } from '@deepseek-ai/dsh-client-ui-primitives'
import { HistoryViewer, type HistoryRpc } from './HistoryViewer.js'

/** Sidebar footer action that opens the project-scoped read-only CLI history panel. */
export const HistorySidebarAction = ({ rpc, wide }: { rpc: HistoryRpc; wide: boolean }) => {
  const [open, setOpen] = useState(false)
  return <>
    <Button onClick={() => setOpen(true)}>{wide ? 'CLI history' : 'History'}</Button>
    <Modal open={open} onClose={() => setOpen(false)} title="CLI history" description="Read-only external CLI sessions for configured projects." className="openduck-history-modal" contentClassName="openduck-history-modal-content">
      <style>{`.openduck-history-modal{width:min(860px,calc(100vw - 32px));max-height:calc(100vh - 32px)}.openduck-history-modal-content{min-height:0;overflow:auto}`}</style><HistoryViewer rpc={rpc} />
    </Modal>
  </>
}
