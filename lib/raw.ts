/**
 * This module implements the lowest layer, which exposes the native
 * interface ({@link RawNetlinkSocket}) to create Netlink sockets and
 * send / receive raw data over them. Its API is intended to
 * mirror [`dgram.Socket`](https://nodejs.org/api/dgram.html).
 * @module
 */

import { EventEmitter } from 'events'
import { constants } from 'os'

// Load the native binding
const binding = require('node-gyp-build')(__dirname + '/..')
type NativeNetlink = any

// Leave first 32 ports preferably for libnl-1
let portCounter = 32

/**
 * Generates a unique port number to bind to, that is supposedly
 * not being used. However this is not a guarantee, especially
 * if you are using native addons that also create Netlink sockets
 * using other libraries (like libnl).
 *
 * Unique port numbers
 * are generated from the PID (lowest 16 bits) and a random number
 * for the highest 16 bits.
 *
 * @returns Unique port number
 */
export function generateLocalPort(): number {
    const pid = process.pid & 0x3FFFFF
    const offset = portCounter
    portCounter = (portCounter + 1) & 0x3FF
    return (offset << 22) | pid
}

/**
 * Options for {@link RawNetlinkSocket}
 */
export interface RawNetlinkSocketOptions {
    /** Local port number to bind to */
    localPort?: number
    /** Local groups mask, deprecated (default: 0, i.e. no groups), BGS: Still used for netfilter */
    localGroups?: number
    /** Enable message peeking (default: true) */
    messagePeeking?: boolean
    /** Buffer size when receiving messages (ignored if message peeking is enabled) (default: 4kb) */
    msgBufferSize?: number

    /** Sets the `SO_RCVBUF` socket value. */
    recvBufferSize: number
    /** Sets the `SO_SNDBUF` socket value. */
    sendBufferSize: number
}

function tryBind(native: NativeNetlink, ...args: any[]) {
    try {
        native.bind(...args)
        return true
    } catch (e) {
        if ((e as any).errno === constants.errno.EADDRINUSE)
            return false
        throw e
    }
}

function retryBind(native: NativeNetlink, groups: number, maxTries: number = 100): number {
    for (let tries = 0; tries < maxTries; tries++) {
        const port = generateLocalPort()
        if (tryBind(native, port, groups)) return port
    }
    throw Error("Couldn't find a free address")
}

export interface MessageInfo {
    /** The sender port */
    port: number
    /** Sender groups bitmask, deprecated */
    groups: number
    /** Set if the message was truncated, indicates original size */
    truncated?: number
}

export interface RawNetlinkSendOptions {
    /**
     * Destination port (default: 0, i.e. the kernel)
     */
    port?: number
    /**
     * Destination groups bitmask, deprecated (default: 0, i.e. no groups)
     */
    groups?: number
}

export interface ErrnoException extends Error {
    name: 'ErrnoException'
    /** name of the syscall that failed to execute */
    syscall: string
    /** error code */
    errno: number
    /** string constant corresponding to {@link errno} */
    code: string
}

interface EventMap {
    message(msg: Buffer, rinfo: MessageInfo): void
    truncatedMessage(msg: Buffer, rinfo: MessageInfo): void
    error(err: ErrnoException): void
    close(): void
}

/**
 * TODO
 *
 * Missing things:
 *  - Credentials passing
 *
 * events:
 * `message`
 * `truncatedMessage`
 * `error`
 * `close`
 */
export class RawNetlinkSocket extends EventEmitter {
    // copy-pasted code for type-safe events
    emit<E extends keyof EventMap>(event: E, ...args: Parameters<EventMap[E]>) { return super.emit(event, ...args) }
    on<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.on(event, listener) }
    once<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.once(event, listener) }
    off<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.off(event, listener) }
    addListener<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.addListener(event, listener) }
    removeListener<E extends keyof EventMap>(event: E, listener: EventMap[E]) { return super.removeListener(event, listener) }

    private readonly __native: NativeNetlink

    /**
     * Create a native Netlink socket, bound to the specified protocol
     * at the specified local address (port).
     *
     * If no port is passed, {@link generateLocalPort} will be used and
     * bind will be retried until we find a free address.
     *
     * @param protocol Netlink protocol to bind to (see {@link Protocol})
     * @param options Socket options
     */
    constructor(protocol: number, options?: RawNetlinkSocketOptions) {
        super()
        let msgBuffer = 0 // by default, do message peeking
        if (options && options.messagePeeking === false)
            msgBuffer = (options && options.msgBufferSize) || 8192 // BGS: Increased size from 4096
        if (typeof protocol !== 'number' || typeof msgBuffer !== 'number')
            throw TypeError('Expected number')
        this.__native = new binding.NativeNetlink(protocol, msgBuffer, this._receive.bind(this), this._error.bind(this))
        try {
            if (options && options.recvBufferSize)
                this.setRecvBufferSize(options && options.recvBufferSize)
            if (options && options.sendBufferSize)
                this.setSendBufferSize(options && options.sendBufferSize)

            let port = options && options.localPort
            const groups = (options && options.localGroups) || 0
            if ((typeof port !== 'undefined' && typeof port !== 'number') || typeof groups !== 'number')
                throw TypeError('Expected number')
            if (typeof port !== 'undefined') {
                this.__native.bind(port, groups)
            } else {
                port = retryBind(this.__native, groups)
            }
        } catch (e) {
            this.__native.close()
            throw e
        }
    }

    private _receive(msg: Buffer, rinfo: MessageInfo) {
        this.emit(rinfo.truncated ? 'truncatedMessage' : 'message', msg, rinfo)
    }

    private _error(error: ErrnoException) {
        this.emit('error', error)
    }

    send(
        msg: Uint8Array | Uint8Array[],
        options?: RawNetlinkSendOptions,
        callback?: (error?: ErrnoException) => void
    ) {
        const port = (options && options.port) || 0
        const groups = (options && options.groups) || 0
        if (typeof port !== 'number' || typeof groups !== 'number')
            throw TypeError('Expected number')
        this.__native.send(port, groups, msg, (error?: ErrnoException) => {
            // FIXME
            if (callback) {
                callback(error)
            } else if (typeof error !== 'undefined') {
                this.emit('error', error)
            }
        })
    }

    /**
     * Close the Netlink socket. After this, all other methods
     * can no longer be called. Messages pending to be sent
     * will be discarded, and its completion callback won't be
     * called.
     */
    close() {
        this.__native.close()
        this.emit('close')
    }

    /**
     * Return the address this socket is currently bound at.
     *
     * @returns Local address
     */
    address(): { port: number, groups: number } {
        return this.__native.address()
    }

    /**
     * References this socket, preventing the event loop from
     * exiting while it is active. The socket is automatically
     * referenced when it is created.
     */
    ref() {
        this.__native.ref()
    }

    /**
     * Unreferences this socket. The socket is automatically
     * referenced when it is created.
     */
    unref () {
        this.__native.unref()
    }

    /** Joins the specified multicast group */
    addMembership(group: number) {
        if (typeof group !== 'number')
            throw TypeError('Expected number')
        this.__native.addMembership(group)
    }

    /** Leaves the specified multicast group */
    dropMembership(group: number) {
        if (typeof group !== 'number')
            throw TypeError('Expected number')
        this.__native.dropMembership(group)
    }

    /** Returns the `SO_RCVBUF` socket receive buffer size in bytes */
    getRecvBufferSize(): number {
        return this.__native.getRecvBufferSize()
    }

    /** Returns the `SO_SNDBUF` socket send buffer size in bytes */
    getSendBufferSize(): number {
        return this.__native.getSendBufferSize()
    }

    /** Sets the `SO_RCVBUF` socket option. Sets the maximum socket receive buffer in bytes. */
    setRecvBufferSize(size: number) {
        if (typeof size !== 'number')
            throw TypeError('Expected number')
        return this.__native.setRecvBufferSize(size)
    }

    /** Sets the `SO_SNDBUF` socket option. Sets the maximum socket send buffer in bytes. */
    setSendBufferSize(size: number) {
        if (typeof size !== 'number')
            throw TypeError('Expected number')
        return this.__native.setSendBufferSize(size)
    }
}
