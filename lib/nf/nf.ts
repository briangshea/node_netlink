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
            /** 
             * NOTE: netfilter will send SUBGROUP << 8 | msg_type as type, look at lower 8 bits only to
             * decode the message type.
             * 
             * @see libnftnl src/common.c line 46
             */
            this.emit('message', omsg.map(x => parseMessage((x.type&nf.__MessageTypeMask), x.data)), rinfo)
        } catch (e) {
            this.emit('invalid', e, omsg, rinfo)
        }
    }

    //addMembership(group: nf.Groups | keyof typeof nf.Groups) {
    //    return this.socket.addMembership(typeof group === 'number' ? group : nf.Groups[group])
    //}
    //
    //dropMembership(group: nf.Groups | keyof typeof nf.Groups) {
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
        data: nf.GenMessage, 
        attrs?: nf.TableAttributes, 
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

    async delTableAction(
        data: nf.GenMessage, 
        attrs?: nf.TableAttributes, 
        options?: NetfilterSendOptions & RequestOptions
    ): Promise<nf.TableMessage[]> {
        const msg = new AttrStream()
        nf.formatTableMessage({ kind: 'table', data, attrs: attrs || {} }, msg)
        const omsg = await this.request(MessageType.DELTABLE, msg.bufs, options)
        return omsg.map(x => {
            if (x.kind !== 'table')
                throw Error(`Unexpected ${x.kind} message received`)
            return x
        })
    }

    async newChainAction(
        data: nf.GenMessage, 
        attrs?: nf.ChainAttributes, 
        options?: NetfilterSendOptions & RequestOptions
    ): Promise<nf.ChainMessage[]> {
        const msg = new AttrStream()
        nf.formatChainMessage({ kind: 'chain', data, attrs: attrs || {} }, msg)
        const omsg = await this.request(MessageType.NEWCHAIN, msg.bufs, options)
        return omsg.map(x => {
            if (x.kind !== 'chain')
                throw Error(`Unexpected ${x.kind} message received`)
            return x
        })
    }

    async delChainAction(
        data: nf.GenMessage, 
        attrs?: nf.ChainAttributes, 
        options?: NetfilterSendOptions & RequestOptions
    ): Promise<nf.ChainMessage[]> {
        const msg = new AttrStream()
        nf.formatChainMessage({ kind: 'chain', data, attrs: attrs || {} }, msg)
        const omsg = await this.request(MessageType.DELCHAIN, msg.bufs, options)
        return omsg.map( x => {
            if( x.kind !== 'chain')
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
