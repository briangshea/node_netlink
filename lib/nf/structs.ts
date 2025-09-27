import { AttrStream } from '../structs'
import { MessageType } from './gen_structs'
import * as nf from './gen_structs'

export type Message =
    TableMessage

export interface TableMessage {
    kind: 'table'
    data: nf.NfGenMessage
    attrs: nf.NfTableAttributes
}

export function parseTableMessage(r: Buffer): TableMessage {
    if (r.length < nf.__LENGTH_NfGenMessage)
        throw Error(`Unexpected Table message length (${r.length})`)

    const data  = nf.parseNfGenMessage(r.subarray(0, nf.__LENGTH_NfGenMessage))
    const attrs = nf.parseNfTableAttrs(r.subarray(nf.__LENGTH_NfGenMessage))

    return { kind: 'table', data, attrs } 
}

export function formatTableMessage(x: TableMessage, out: AttrStream) {
    out.emit(nf.formatNfGenMessage(x.data))
    out.emit(nf.formatNfTableAttrs(x.attrs))
}


const parseFns: { [t in MessageType]?: (r: Buffer) => Message } = {
    [MessageType.NEWTABLE]: parseTableMessage
}

export function parseMessage(t: MessageType, r: Buffer): Message {
    if (!{}.hasOwnProperty.call(parseFns, t))
        throw Error(`Unsupported message type ${t}`)
    return parseFns[t]!(r)
}

// Export rest of types
export * from './gen_structs'
