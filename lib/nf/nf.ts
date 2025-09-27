/**
 * This module implements the NETFILTER interface on top of `netlink`.
 * @module
 */

import { EventEmitter } from 'events'

import { MessageInfo, RawNetlinkSocketOptions } from '../raw'
import { createNetlink, NetlinkSocket, NetlinkSocketOptions, NetlinkSendOptions, RequestOptions } from '../netlink'
import { Protocol, FlagsGet } from '../constants'
import { NetlinkMessage, AttrStream } from '../structs'
import { parseMessage, Message, MessageType } from './structs'
import * as nf from './structs'

export interface NetfilterSocketOptions {
}

export interface NetfilterSendOptions extends NetlinkSendOptions {
}

interface EventMap {
    invalid(err: any, msg: NetlinkMessage[], rinfo: MessageInfo): void
    message(msg: Message[], rinfo: MessageInfo): void
}

export class NfNetlinkSocket extends EventEmitter {
    // copy-pasted code for type-safe events
    emit<E extends keyof EventMap>(event: E, ...args: Parameters<EventMap[E]>) { return super.emit(event, ...args) }
    on<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.on(event, listener) }
    once<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.once(event, listener) }
    off<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.off(event, listener) }
    addListener<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.addListener(event, listener) }
    removeListener<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.removeListener(event, listener) }

    readonly socket: NetlinkSocket

    constructor(socket: NetlinkSocket, options?: NetfilterSocketOptions) {
        super()
        this.socket = socket
        this.socket.on('message', this._receive.bind(this))
    }

    private _receive(omsg: NetlinkMessage[], rinfo: MessageInfo) {
        try {
            this.emit('message', omsg.map(x => parseMessage(x.type, x.data)), rinfo)
        } catch (e) {
            this.emit('invalid', e, omsg, rinfo)
        }
    }

    /** Do we need to expose addMembership? */
    //addMembership(group: nf.MulticastGroups | keyof typeof nf.MulticastGroups) {
    //    return this.socket.addMembership(typeof group === 'number' ? group : nf.MulticastGroups[group])
    //}

    /** Do we need to expose dropMembership? */
    //dropMembership(group: nf.MulticastGroups | keyof typeof nf.MulticastGroups) {
    //    return this.socket
    //}

    async send(
        type: MessageType,
        data: Uint8Array | Uint8Array[],
        options?: NetfilterSendOptions & RequestOptions,
        callback?: (error?: Error) => any,
    ) {
        return this.socket.send(type, data, options, callback)
    }

    async request(
        type: MessageType,
        data: Uint8Array | Uint8Array[],
        options?: NetfilterSendOptions & RequestOptions
    ): Promise<Message[]> {
        const [msg, rinfo] = await this.socket.request(type, data, options)
        return msg.map(x => parseMessage(x.type, x.data))
    }

    async newTableAction(
        data: nf.NfGenMessage, 
        attrs?: nf.NfTableAttributes, 
        options?: NetfilterSendOptions & RequestOptions
    ): Promise<nf.TableMessage[]> {
        const msg = new AttrStream()
        nf.formatTableMessage({ kind: 'table', data, attrs: attrs || {} }, msg)
        const omsg = await this.request(MessageType.NEWTABLE, msg.bufs, options)
        return omsg.map(x => {
            if (x.kind !== 'table')
                throw Error(`Unexpected ${x.kind} message received`)
            return x
        })
    }
}

export function createNfNetlink(
    options?: RawNetlinkSocketOptions & NetfilterSocketOptions
): NfNetlinkSocket {
    const socket = createNetlink(Protocol.NETFILTER, options)
    return new NfNetlinkSocket(socket, options)
}
