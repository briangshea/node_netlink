import { AttrStream } from '../structs'
import { MessageType } from './gen_structs'
import * as nf from './gen_structs'

export type Message =
    TableMessage |
    ChainMessage

export interface TableMessage {
    kind: 'table'
    action?: string
    data: nf.GenMessage
    attrs: nf.TableAttributes
}

export function parseNewTableMessage(r: Buffer): TableMessage {
    if (r.length < nf.__LENGTH_GenMessage)
        throw Error(`Unexpected Table message length (${r.length})`)

    const data  = nf.parseGenMessage(r.subarray(0, nf.__LENGTH_GenMessage))
    const attrs = nf.parseTableAttrs(r.subarray(nf.__LENGTH_GenMessage))

    return { kind: 'table', action: 'create', data, attrs } 
}

export function parseDelTableMessage(r: Buffer): TableMessage {
    if (r.length < nf.__LENGTH_GenMessage)
        throw Error(`Unexpected Table message length (${r.length})`)

    const data  = nf.parseGenMessage(r.subarray(0, nf.__LENGTH_GenMessage))
    const attrs = nf.parseTableAttrs(r.subarray(nf.__LENGTH_GenMessage))

    return { kind: 'table', action: 'delete', data, attrs } 
}

export function formatTableMessage(x: TableMessage, out: AttrStream) {
    out.emit(nf.formatGenMessage(x.data))
    out.emit(nf.formatTableAttrs(x.attrs))
}

export interface ChainMessage {
    kind: 'chain'
    action?: string
    data: nf.GenMessage
    attrs: nf.ChainAttributes
}

export function parseNewChainMessage(r: Buffer): ChainMessage {
    if (r.length < nf.__LENGTH_GenMessage)
        throw Error(`Unexpected Table message length (${r.length})`)

    const data  = nf.parseGenMessage(r.subarray(0, nf.__LENGTH_GenMessage))
    const attrs = nf.parseChainAttrs(r.subarray(nf.__LENGTH_GenMessage))

    return { kind: 'chain', action: 'create', data, attrs } 
}

export function parseDelChainMessage(r: Buffer): ChainMessage {
    if (r.length < nf.__LENGTH_GenMessage)
        throw Error(`Unexpected Table message length (${r.length})`)

    const data  = nf.parseGenMessage(r.subarray(0, nf.__LENGTH_GenMessage))
    const attrs = nf.parseChainAttrs(r.subarray(nf.__LENGTH_GenMessage))

    return { kind: 'chain', action: 'delete', data, attrs } 
}

export function formatChainMessage(x: ChainMessage, out: AttrStream) {
    out.emit(nf.formatGenMessage(x.data))
    out.emit(nf.formatChainAttrs(x.attrs))
}


const parseFns: { [t in MessageType]?: (r: Buffer) => Message } = {
    [MessageType.NEWTABLE]: parseNewTableMessage,
    [MessageType.DELTABLE]: parseDelTableMessage,
    [MessageType.NEWCHAIN]: parseNewChainMessage,
    [MessageType.DELCHAIN]: parseDelChainMessage
}

export function parseMessage(t: MessageType, r: Buffer): Message {
    if (!{}.hasOwnProperty.call(parseFns, t))
        throw Error(`Unsupported message type ${t}`)
    return parseFns[t]!(r)
}

// Export rest of types
export * from './gen_structs'
