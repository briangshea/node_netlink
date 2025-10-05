import { BaseObject, BaseExpandableStruct, StreamData } from '../structs'
import * as structs from '../structs'

export const __MessageTypeMask = 0xFF;

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
	GETSETELEM_RESET
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
    NONE                  = 0,
	CONNTRACK_NEW         = (1<<0),
	CONNTRACK_UPDATE      = (1<<1),
	CONNTRACK_DESTROY     = (1<<2),
	CONNTRACK_EXP_NEW     = (1<<3),
	CONNTRACK_EXP_UPDATE  = (1<<4),
	CONNTRACK_EXP_DESTROY = (1<<5),
	NFTABLES              = (1<<6),
	ACCT_QUOTA            = (1<<7),
	NFTRACE               = (1<<8),
};

export enum Family {
    UNSPEC = "UNSPEC",
	INET   = "INET",
	IPV4   = "IPV4",
	ARP    = "ARP",
	NETDEV = "NETDEV",
	BRIDGE = "BRIDGE",
	IPV6   = "IPV6",
	DECNET = "DECBET",
    /** Catch all for any unknown family type */
    __unknown_family = "UNKNOWN_FAMILY"
}

/** Parses the attributes of a {@link Family} object */
export function parseFamily(x: number) : Family {
    switch (x) {
        case 0: return Family.UNSPEC
        case 1: return Family.INET
        case 2: return Family.IPV4
        case 3: return Family.ARP
        case 4: return Family.NETDEV
        case 5: return Family.BRIDGE
        case 6: return Family.IPV6
        case 7: return Family.DECNET
        default: return Family.__unknown_family
    }
}

/** Encodes a {@link Family} object into a stream of attributes */
export function formatFamily(x: Family) : number {
    switch (x) {
        case Family.UNSPEC: return 0
        case Family.INET:   return 1
        case Family.IPV4:   return 2
        case Family.ARP:    return 3
        case Family.NETDEV: return 4
        case Family.BRIDGE: return 5
        case Family.IPV6:   return 6
        case Family.DECNET: return 7
        default: return 0;
    }
}

export enum Verdict {
    CONTINUE = "Continue",
    BREAK = "Break",
    JUMP = "Jump",
    GOTO = "Goto",
    RETURN = "Return",
    __unknown_verdict = "Unkown Verdict"
}

/** Parses the attributes of a {@link Verdict} object */
export function parseVerdict(x: number) : Verdict {
    switch (x) {
        case 0: return Verdict.CONTINUE
        case 1: return Verdict.BREAK
        case 2: return Verdict.JUMP
        case 3: return Verdict.GOTO
        case 4: return Verdict.RETURN
        default: return Verdict.__unknown_verdict
    }
}

/** Encodes a {@link Verdict} object into a stream of attributes */
export function formatVerdict(x: Verdict) : number {
    switch (x) {
        case Verdict.CONTINUE: return -1
        case Verdict.BREAK:    return -2
        case Verdict.JUMP:     return -3
        case Verdict.GOTO:     return -4
        case Verdict.RETURN:   return -5
        default: return 0;
    }
}

export const __LENGTH_GenMessage = 4;

/** General form of address family dependent GenMessage. **/
export interface GenMessage extends BaseObject {
    family?: Family
    
    version?: number
    
    res_id?: number
};

/** Parses the attributes of a {@link GenMessage} object */
export function parseGenMessage(r: Buffer): GenMessage {
    if (r.length !== __LENGTH_GenMessage) throw Error('Unexpected length for NetfilterGenMsg')
    const x: GenMessage = {}
    x.family = parseFamily(structs.readU8.call(r, 0))
    x.version = structs.readU8.call(r, 1)
    x.res_id = structs.readU16.call(r, 2)
    return x
};

/** Encodes a {@link GenMessage} object into a stream of attributes */
export function formatGenMessage(x: GenMessage, r: Buffer = Buffer.alloc(__LENGTH_GenMessage)): Buffer {
    if (r.length !== __LENGTH_GenMessage) throw Error('Unexpected length for NetfilterGenMsg')
    x.family && structs.writeU8.call(r, formatFamily(x.family), 0)
    x.version && structs.writeU8.call(r, x.version, 1)
    x.res_id && structs.writeU16.call(r, x.res_id, 2)
    return r
};

/** Table Messages */

/** Attributes used in Table Messages */
export interface TableAttributes extends BaseObject {
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

export function parseTableAttrs(r: Buffer): TableAttributes {
    return structs.getObject(r, {
        1: (data, obj) => obj.name = data,                                              // NFTA_TABLE_NAME
        2: (data, obj) => obj.flags = parseTableFlags(structs.readU32.call(data, 0)),   // NFTA_TABLE_FLAGS
        3: (data, obj) => obj.use = structs.readU32.call(data, 0),                      // NFTA_TABLE_USE
        4: (data, obj) => obj.handle = structs.readU64be.call(data, 0),                 // NFTA_TABLE_HANDLE
        5: (data, obj) => obj.pad5 = structs.readU32.call(data, 0),                     // NFTA_TABLE_PAD
        6: (data, obj) => obj.user = data,                                              // NFTA_TABLE_USER
        7: (data, obj) => obj.owner = structs.readU32.call(data, 0),                    // NFTA_TABLE_OWNER
    })
};

export function formatTableAttrs(x: TableAttributes): StreamData {
    return structs.putObject(x, {
        name:   (data, obj) => data.push(1, obj.name!),                   // NFTA_TABLE_NAME
        flags:  (data, obj) => data.push(2, structs.putU32(formatTableFlags(obj.flags!))),  // NFTA_TABLE_FLAGS
        use:    (data, obj) => data.push(3, structs.putU32(obj.use!)),    // NFTA_TABLE_USE
        handle: (data, obj) => data.push(4, structs.putU64(obj.handle!)), // NFTA_TABLE_HANDLE
        user:   (data, obj) => data.push(6, obj.user!),                   // NFTA_TABLE_USER
        owner:  (data, obj) => data.push(7, structs.putU32(obj.owner!))   // NFTA_TABLE_OWNER
    })
};

/** Chain Messages */
export enum HookNum {
    PREROUTING        = "PREROUTING",
    INPUT             = "INPUT",
    FORWARD           = "FORWARD",
    OUTPUT            = "OUTPUT",
    POSTROUTING       = "POSTROUTING",
    INGRESS           = "INGRESS",
    __unknown_hooknum = "UNKNOWN_HOOK"
}

export enum NetDevHookNum {
    INGRESS           = "INGRESS",
    __unknown_devhook = "UNKNOWN_DEVHOOK"
}

export enum ArpHookNum {
    APR_IN      = "ARP_IN",
    ARP_OUT     = "ARP_OUT",
    ARP_FORWARD = "ARP_FORWARD",
    __unknown_ArpHookNum = "UNKNOWN_ArpHookNum"
}

/** Parses the attributes of a {@link HookNum} object */
export function parseHookNum(x: number, family: Family) : HookNum | NetDevHookNum | ArpHookNum {
    switch (family) {
    case Family.IPV4:
    case Family.IPV6:
    case Family.INET:
    case Family.BRIDGE:    
        switch (x) {
        case 0: return  HookNum.PREROUTING
        case 1: return  HookNum.INPUT
        case 2: return  HookNum.FORWARD
        case 3: return  HookNum.OUTPUT
        case 4: return  HookNum.POSTROUTING
        case 5: return  HookNum.INGRESS
        default: return HookNum.__unknown_hooknum
        }
    case Family.ARP:
        switch (x) {
        case 0: return ArpHookNum.APR_IN
        case 1: return ArpHookNum.ARP_OUT
        case 2: return ArpHookNum.ARP_FORWARD
        default: return ArpHookNum.__unknown_ArpHookNum
        }
    case Family.NETDEV:
        switch (x) {
        case 0: return  NetDevHookNum.INGRESS
        default: return NetDevHookNum.__unknown_devhook
        }
    }
    throw(Error(`Unknown Family type does not support HookNum.`))
}

/** Encodes a {@link HookNum} object into a stream of attribute value */
export function formatHookNum(x: HookNum | NetDevHookNum | ArpHookNum) : number {
    if( typeof x === typeof HookNum ) {
        switch (x) {
            case HookNum.PREROUTING: return 0
            case HookNum.INPUT:      return 1
            case HookNum.FORWARD:    return 2
            case HookNum.OUTPUT:     return 3
            case HookNum.POSTROUTING:return 4
            case HookNum.INGRESS:    return 5
            default: throw(Error(`Unknown hooknum.`))
        }
    } else if ( typeof x === typeof NetDevHookNum ) {
        switch (x) {
            case NetDevHookNum.INGRESS: return 0
            default: throw(Error(`Unknown devhook.`))
        }
    } else if ( typeof x === typeof ArpHookNum ) {
        switch (x) {
            case ArpHookNum.APR_IN:      return 0
            case ArpHookNum.ARP_OUT:     return 1
            case ArpHookNum.ARP_FORWARD: return 2
            default: throw(Error(`Unknown ArpHookNum.`))
        }
    }

    throw(Error(`Unknown HookNum type.`))
}

export interface Devices extends BaseObject {
    name: Buffer[]     // array of attributes
}

/** Parses the attributes of a {@link Devices} object */
export function parseDevices(r: Buffer): Devices {
    return structs.getObject(r, {
        1: (data, obj) => obj.name?.push(data)   // NFTA_DEVICE_NAME
    })
}

/** Encodes a {@link Devices} object into a stream of attributes */
export function formatDevices(x: Devices): StreamData {
    return structs.putObject(x, {
        devices: (data, obj) => data.push(1, obj.name!)   // NFTA_DEVICE_NAME
    })
}

export interface Hook extends BaseObject {
    hooknum?: number        // At the time of decoding, we do not know to which family the chain belongs

    priority?: number
    
    dev?: Buffer

    devices?: Devices[]     // nested
}

/** Parse the attributes of a {@link Hook} object */
export function parseHook(r: Buffer): Hook {
    return structs.getObject(r, {
        1: (data, obj) => obj.hooknum = structs.readU32.call(data, 0),   // NFTA_HOOK_NUM
        2: (data, obj) => obj.priority = structs.readU32.call(data, 0),  // NFTA_HOOK_PRIORITY
        3: (data, obj) => obj.dev = data,                                // NFTA_HOOK_DEV
        4: (data, obj) => obj.devices = structs.getArray(data, x =>  parseDevices(x))   // NFTA_HOOK_DEVICES (array, nested)
    })
}

/** Encodes a {@link Hook} object into a stream of attributes */
export function formatHook(x: Hook): StreamData {
    return structs.putObject(x, {
        hooknum:   (data, obj) => data.push(1, structs.putU32(obj.hooknum!)),  // NFTA_HOOK_NUM
        priority:  (data, obj) => data.push(2, structs.putU32(obj.priority!)), // NFTA_HOOK_PRIORITY
        dev:       (data, obj) => data.push(3, obj.dev!),                      // NFTA_HOOK_DEV
        devices:   (data, obj) => data.push(4, structs.putArray(obj.devices!, x => formatDevices(x)))  // NFTA_HOOK_DEVICES
    })
}

export interface ChainCounters extends BaseObject {
    bytes?: bigint
    packets?: bigint
}

/** Parse the attributes of a {@link ChainCounters} object */
export function parseChainCounters(r: Buffer): ChainCounters {
    return structs.getObject(r, {
        1: (data, obj) => obj.bytes = structs.readU64.call(data, 0),  // NFTA_COUNTER_BYTES
        2: (data, obj) => obj.packets = structs.readU64.call(data, 0) // NFTA_COUNTER_PACKETS
    })
}

/** Encodes a {@link ChainCounters} object into a stream of attributes */
export function formatChainCounters(x: ChainCounters): StreamData {
    return structs.putObject(x, {
        bytes:   (data, obj) => data.push(1, structs.putU64(obj.bytes!)),  // NFTA_COUNTER_BYTES
        packets: (data, obj) => data.push(2, structs.putU64(obj.packets!)) // NFTA_COUNTER_PACKETS
    })
}

export interface ChainAttributes extends BaseObject {
    table?: Buffer

    handle?: bigint

    name? : Buffer

    hook?: Hook

    policy?: Verdict

    use?: number

    type?: Buffer

    counters?: ChainCounters

    pad9?: Buffer

    flags?: number

    chain_id?: number

    user?: Buffer
}

/** Parses the attributes of a {@link ChainMessage} object */
export function parseChainAttrs(r: Buffer): ChainAttributes {
    return structs.getObject(r, {
         1: (data, obj) => obj.table = data,                                             // NFTA_CHAIN_TABLE
         2: (data, obj) => obj.handle = structs.readU64be.call(data, 0),                 // NFTA_CHAIN_HANDLE
         3: (data, obj) => obj.name = data,                                              // NFTA_CHAIN_NAME
         4: (data, obj) => obj.hook = parseHook(data),                                   // NFTA_CHAIN_HOOK (nested)
         5: (data, obj) => obj.policy = parseVerdict(structs.readU32.call(data, 0)),     // NFTA_CHAIN_POLICY
         6: (data, obj) => obj.use = structs.readU32.call(data, 0),                      // NFTA_CHAIN_USE
         7: (data, obj) => obj.type = data,                                              // NFTA_CHAIN_TYPE
         8: (data, obj) => obj.counters = parseChainCounters(data),                      // NFTA_CHAIN_COUNTERS (nested)
         9: (data, obj) => obj.pad9 = data,                                              // NFTA_CHAIN_PAD
        10: (data, obj) => obj.flags = structs.readU32.call(data, 0),                    // NFTA_CHAIN_FLAGS
        11: (data, obj) => obj.chain_id = structs.readU32.call(data, 0),                 // NFTA_CHAIN_ID
        12: (data, obj) => obj.user = data,                                              // NFTA_CHAIN_USERDATA
    })
}

/** Encode a {@link ChainAttributes} object into a stream of attributes */
export function formatChainAttrs(x: ChainAttributes): StreamData {
    return structs.putObject(x, {
        table:    (data, obj) => data.push(1,  obj.table!),                                 // NFTA_CHAIN_TABLE
        handle:   (data, obj) => data.push(2,  structs.putU64(obj.handle!)),                // NFTA_CHAIN_HANDLE
        name:     (data, obj) => data.push(3,  obj.name!),                                  // NFTA_CHAIN_NAME
        hook:     (data, obj) => data.push(4,  formatHook(obj.hook!)),                      // NFTA_CHAIN_HOOK
        policy:   (data, obj) => data.push(5,  structs.putU32(formatVerdict(obj.policy!))), // NFTA_CHAIN_POLICY
        use:      (data, obj) => data.push(6,  structs.putU32(obj.use!)),                   // NFTA_CHAIN_USE
        type:     (data, obj) => data.push(7,  obj.type!),                                  // NFTA_CHAIN_TYPE
        counters: (data, obj) => data.push(8,  formatChainCounters(obj.counters!)),         // NFTA_CHAIN_COUNTERS
        pad9:     (data, obj) => data.push(9,  obj.pad9!),                                  // NFTA_CHAIN_PAD
        flags:    (data, obj) => data.push(10, structs.putU32(obj.flags!)),                 // NFTA_CHAIN_FLAGS
        chain_id: (data, obj) => data.push(11, structs.putU32(obj.chain_id!)),              // NFTA_CHAIN
        user:     (data, obj) => data.push(12, obj.user!)                                   // NFTA_CHAIN_USERDATA
    })
}

