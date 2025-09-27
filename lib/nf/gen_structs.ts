import { BaseObject, BaseExpandableStruct, StreamData } from '../structs'
import * as structs from '../structs'

export enum MessageType {
    NEWTABLE,
	GETTABLE,
	DELTABLE,
	NEWCHAIN,
	GETCHAIN,
	DELCHAIN,
	NEWRULE,
	GETRULE,
	DELRULE,
	NEWSET,
	GETSET,
	DELSET,
	NEWSETELEM,
	GETSETELEM,
	DELSETELEM,
	NEWGEN,
	GETGEN,
	TRACE,
	NEWOBJ,
	GETOBJ,
	DELOBJ,
	GETOBJ_RESET,
	NEWFLOWTABLE,
	GETFLOWTABLE,
	DELFLOWTABLE,
	GETRULE_RESET,
	DESTROYTABLE,
	DESTROYCHAIN,
	DESTROYRULE,
	DESTROYSET,
	DESTROYSETELEM,
	DESTROYOBJ,
	DESTROYFLOWTABLE,
	GETSETELEM_RESET,
	MAX
};

export enum Subsystem {
    NONE = 0,
    CTNETLINK,
    CTNETLINK_EXP,
    QUEUE,
    ULOG,
    OSF,
    IPSET,
    ACCT,
    CTNETLINK_TIMEOUT,
    CTHELPER,
    NFTABLES,
    NFT_COMPAT,
    HOOK,
    COUNT
};

export enum Groups {
    NONE = 0,
	CONNTRACK_NEW,
	CONNTRACK_UPDATE,
	CONNTRACK_DESTROY,
	CONNTRACK_EXP_NEW,
	CONNTRACK_EXP_UPDATE,
	CONNTRACK_EXP_DESTROY,
	NFTABLES,
	ACCT_QUOTA,
	NFTRACE,
	__NFNLGRP_MAX,
};

export const __LENGTH_NfGenMessage = 4;

/** General form of address family dependent message. **/
export interface NfGenMessage extends BaseObject {
    family?: number
    
    version?: number
    
    res_id?: number
};

/** Parses the attributes of a {@link NfGenMessage} object */
export function parseNfGenMessage(r: Buffer): NfGenMessage {
    if (r.length !== __LENGTH_NfGenMessage) throw Error('Unexpected length for NetfilterGenMsg')
    const x: NfGenMessage = {}
    x.family = structs.readU8.call(r, 0)
    x.version = structs.readU8.call(r, 1)
    x.res_id = structs.readU16.call(r, 2)
    return x
};

/** Encodes a {@link NfGenMessage} object into a stream of attributes */
export function formatNfGenMessage(x: NfGenMessage, r: Buffer = Buffer.alloc(__LENGTH_NfGenMessage)): Buffer {
    if (r.length !== __LENGTH_NfGenMessage) throw Error('Unexpected length for NetfilterGenMsg')
    x.family && structs.writeU8.call(r, x.family, 0)
    x.version && structs.writeU8.call(r, x.version, 1)
    x.res_id && structs.writeU16.call(r, x.res_id, 2)
    return r
};

/** Attributes used in Table Messages */
export interface NfTableAttributes extends BaseObject {
    name?: Buffer
    
    flags?: TableFlags

    use?: number

    handle?: bigint

    pad5?: number

    user?: Buffer

    owner?: number
};

/** Flas for Table Message flag Attribute */
export interface TableFlags {
    dormant?: Boolean

    owner?: Boolean

    __unknown?: number
}

/** Parses the flags in a {@link TableFlags} bitmask */
export function parseTableFlags(r: number): TableFlags {
    const x: TableFlags = {}
    x.dormant = Boolean(r & (1 << 0)) // NFT_TABLE_F_DORMANT
    x.owner =   Boolean(r & (1 << 1)) // NFT_TABLE_F_OWNER
    return x
};

/** Encodes a {@link TableFlags} bitmask */
export function formatTableFlags(x: TableFlags): number {
    let r = x.__unknown || 0
    if(x.dormant) r |= 1 << 0 // NFT_TABLE_F_DORMANT
    if(x.owner)   r |= 1 << 1 // NFT_TABLE_F_OWNER
    return r
};

export function parseNfTableAttrs(r: Buffer): NfTableAttributes {
    return structs.getObject(r, {
        1: (data, obj) => obj.name = data,                            // NFTA_TABLE_NAME
        2: (data, obj) => obj.flags = parseTableFlags(structs.readU32.call(data, 0)),  // NFTA_TABLE_FLAGS
        3: (data, obj) => obj.use = structs.readU32.call(data, 0),    // NFTA_TABLE_USE
        4: (data, obj) => obj.handle = structs.readU64.call(data, 0), // NFTA_TABLE_HANDLE
        5: (data, obj) => obj.pad5 = structs.readU32.call(data, 0),   // NFTA_TABLE_PAD
        6: (data, obj) => obj.user = data,                            // NFTA_TABLE_USER
        7: (data, obj) => obj.owner = structs.readU32.call(data, 0),  // NFTA_TABLE_OWNER
    })
};

export function formatNfTableAttrs(x: NfTableAttributes): StreamData {
    return structs.putObject(x, {
        name:   (data, obj) => data.push(1, obj.name!),                   // NFTA_TABLE_NAME
        flags:  (data, obj) => data.push(2, structs.putU32(formatTableFlags(obj.flags!))),  // NFTA_TABLE_FLAGS
        use:    (data, obj) => data.push(3, structs.putU32(obj.use!)),    // NFTA_TABLE_USE
        handle: (data, obj) => data.push(4, structs.putU64(obj.handle!)), // NFTA_TABLE_HANDLE
        user:   (data, obj) => data.push(6, obj.user!),                   // NFTA_TABLE_USER
        owner:  (data, obj) => data.push(7, structs.putU32(obj.owner!))   // NFTA_TABLE_OWNER
    })
};

