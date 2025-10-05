/**
 * netfilter_netlink interface
 *
 * FIXME:
 * This excludes if_link.h and its associated headers,
 * these types have been placed in ifla.ts. Therefore
 * {@link Link} is defined here, but {@link LinkAttrs} is not.
 *
 * Based on
 *   <linux/netfilter/nfnetlink.h>
 *   <linux/netfilter/nf_tables.h>
 * @module
 */

import { Family, Hook, Verdict } from '../lib/nf/gen_structs'
import { TypeStore, data, bool, flag, u8, u16, u32, u64, s8, s16, s32, s64, f32, f64, string, array, map, asflags } from './_base'

const types: TypeStore = {
    // GENERIC //

    MessageType: { kind: 'enum', orig: 'nf_tables_msg_types', values: [
        { value: 0,  name: 'NEWTABLE',         orig : 'NFT_MSG_NEWTABLE' },
        { value: 1,  name: 'GETTABLE',         orig : 'NFT_MSG_GETTABLE' },
        { value: 2,  name: 'DELTABLE',         orig : 'NFT_MSG_DELTABLE' },
        { value: 3,  name: 'NEWCHAIN',         orig : 'NFT_MSG_NEWCHAIN' },
        { value: 4,  name: 'GETCHAIN',         orig : 'NFT_MSG_GETCHAIN' },
        { value: 5,  name: 'DELCHAIN',         orig : 'NFT_MSG_DELCHAIN' },
        { value: 6,  name: 'NEWRULE',          orig : 'NFT_MSG_NEWRULE' },
        { value: 7,  name: 'GETRULE',          orig : 'NFT_MSG_GETRULE' },
        { value: 8,  name: 'DELRULE',          orig : 'NFT_MSG_DELRULE' },
        { value: 9,  name: 'NEWSET',           orig : 'NFT_MSG_NEWSET' },
        { value: 10, name: 'GETSET',           orig : 'NFT_MSG_GETSET' },
        { value: 12, name: 'DELSET',           orig : 'NFT_MSG_DELSET' },
        { value: 13, name: 'NEWSETELEM',       orig : 'NFT_MSG_NEWSETELEM' },
        { value: 14, name: 'GETSETELEM',       orig : 'NFT_MSG_GETSETELEM' },
        { value: 15, name: 'DELSETELEM',       orig : 'NFT_MSG_DELSETELEM' },
        { value: 16, name: 'NEWGEN',           orig : 'NFT_MSG_NEWGEN' },
        { value: 17, name: 'GETGEN',           orig : 'NFT_MSG_GETGEN' },
        { value: 18, name: 'TRACE',            orig : 'NFT_MSG_TRACE' },
        { value: 19, name: 'NEWOBJ',           orig : 'NFT_MSG_NEWOBJ' },
        { value: 20, name: 'GETOBJ',           orig : 'NFT_MSG_GETOBJ' },
        { value: 21, name: 'DELOBJ',           orig : 'NFT_MSG_DELOBJ' },
        { value: 22, name: 'GETOBJ_RESET',     orig : 'NFT_MSG_GETOBJ_RESET' },
        { value: 23, name: 'NEWFLOWTABLE',     orig : 'NFT_MSG_NEWFLOWTABLE' },
        { value: 24, name: 'GETFLOWTABLE',     orig : 'NFT_MSG_GETFLOWTABLE' },
        { value: 25, name: 'DELFLOWTABLE',     orig : 'NFT_MSG_DELFLOWTABLE' },
        { value: 26, name: 'GETRULE_RESET',    orig : 'NFT_MSG_GETRULE_RESET' },
        { value: 27, name: 'DESTROYTABLE',     orig : 'NFT_MSG_DESTROYTABLE' },
        { value: 28, name: 'DESTROYCHAIN',     orig : 'NFT_MSG_DESTROYCHAIN' },
        { value: 29, name: 'DESTROYRULE',      orig : 'NFT_MSG_DESTROYRULE' },
        { value: 30, name: 'DESTROYSET',       orig : 'NFT_MSG_DESTROYSET' },
        { value: 31, name: 'DESTROYSETELEM',   orig : 'NFT_MSG_DESTROYSETELEM' },
        { value: 32, name: 'DESTROYOBJ',       orig : 'NFT_MSG_DESTROYOBJ' },
        { value: 33, name: 'DESTROYFLOWTABLE', orig : 'NFT_MSG_DESTROYFLOWTABLE' },
        { value: 34, name: 'GETSETELEM_RESET', orig : 'NFT_MSG_GETSETELEM_RESET' },
    ]},

    Subsystem: { kind: 'enum', orig: 'nfnetlink_subsystem', docs: [ 
        'Netfilter subsystem types.'
    ], values: [
        { value:  0, name: 'NONE',              orig: 'NFNL_SUBSYS_NONE' },
        { value:  1, name: 'CTNETLINK',         orig: 'NFNL_SUBSYS_CTNETLINK' },
        { value:  2, name: 'CTNETLINK_EXP',     orig: 'NFNL_SUBSYS_CTNETLINK_EXP' },
        { value:  3, name: 'QUEUE',             orig: 'NFNL_SUBSYS_QUEUE' },
        { value:  4, name: 'ULOG',              orig: 'NFNL_SUBSYS_ULOG' },
        { value:  5, name: 'OSF',               orig: 'NFNL_SUBSYS_OSF' },
        { value:  6, name: 'IPSET',             orig: 'NFNL_SUBSYS_IPSET' },
        { value:  7, name: 'ACCT',              orig: 'NFNL_SUBSYS_ACCT' },
        { value:  8, name: 'CTNETLINK_TIMEOUT', orig: 'NFNL_SUBSYS_CTNETLINK_TIMEOUT' },
        { value:  9, name: 'CTHELPER',          orig: 'NFNL_SUBSYS_CTHELPER' },
        { value: 10, name: 'NFTABLES',          orig: 'NFNL_SUBSYS_NFTABLES' },
        { value: 11, name: 'NFT_COMPAT',        orig: 'NFNL_SUBSYS_NFT_COMPAT' },
        { value: 12, name: 'HOOK',              orig: 'NFNL_SUBSYS_HOOK' },
        { value: 13, name: 'COUN',              orig: 'NFNL_SUBSYS_COUNT' }
    ]},

    Groups: { kind: 'enum', orig: 'nfnetlink_groups', docs: [
        'Netfilter group types.'
    ], values: [
        { value:  0     , name: 'NONE',                  orig: 'NFNLGRP_NONE' },
        { value:  (1<<0), name: 'CONNTRACK_NEW',         orig: 'NFNLGRP_CONNTRACK_NEW' },
        { value:  (1<<1), name: 'CONNTRACK_UPDATE',      orig: 'NFNLGRP_CONNTRACK_UPDATE' },
        { value:  (1<<2), name: 'CONNTRACK_DESTROY',     orig: 'NFNLGRP_CONNTRACK_DESTROY' },
        { value:  (1<<3), name: 'CONNTRACK_EXP_NEW',     orig: 'NFNLGRP_CONNTRACK_EXP_NEW' },
        { value:  (1<<4), name: 'CONNTRACK_EXP_UPDATE',  orig: 'NFNLGRP_CONNTRACK_EXP_UPDATE' },
        { value:  (1<<5), name: 'CONNTRACK_EXP_DESTROY', orig: 'NFNLGRP_CONNTRACK_EXP_DESTROY' },
        { value:  (1<<6), name: 'NFTABLES',              orig: 'NFNLGRP_NFTABLES' },
        { value:  (1<<7), name: 'ACCT_QUOTA',            orig: 'NFNLGRP_ACCT_QUOTA' },
        { value:  (1<<8), name: 'NFTRACE',               orig: 'NFNLGRP_NFTRACE' }
    ]},

    Family: { kind: 'enum', orig: 'nf_tables_family', docs: [
        'Netfilter family types.'
    ], values: [
        { value: 0, name: 'UNSPEC', orig: 'NFPROTO_UNSPEC' },
        { value: 1, name: 'INET',   orig: 'NFPROTO_INET' },
        { value: 2, name: 'IPV4',   orig: 'NFPROTO_IPV4' },
        { value: 3, name: 'ARP',    orig: 'NFPROTO_ARP' },
        { value: 4, name: 'NETDEV', orig: 'NFPROTO_NETDEV' },
        { value: 5, name: 'BRIDGE', orig: 'NFPROTO_BRIDGE' },
        { value: 6, name: 'IPV6',   orig: 'NFPROTO_IPV6' },
        { value: 7, name: 'DECNET', orig: 'NFPROTO_DECNET' }
    ]},

    Verdict: { kind: 'enum', orig: 'nft_verdicts', docs: [
        'enum nft_verdicts - nf_tables internal verdicts',
        '@NFT_CONTINUE: continue evaluation of the current rule',
        '@NFT_BREAK: terminate evaluation of the current rule',
        '@NFT_JUMP: push the current chain on the jump stack and jump to a chain',
        '@NFT_GOTO: jump to a chain without pushing the current chain on the jump stack',
        '@NFT_RETURN: return to the topmost chain on the jump stack',
        'The nf_tables verdicts share their numeric space with the netfilter verdicts.',
    ], values: [
        { value: -1, name: 'CONTINUE', orig: 'NFT_CONTINUE' },
        { value: -2, name: 'BREAK',    orig: 'NFT_BREAK' },
        { value: -3, name: 'JUMP',     orig: 'NFT_JUMP' },
        { value: -4, name: 'GOTO',     orig: 'NFT_GOTO' },
        { value: -5, name: 'RETURN',   orig: 'NFT_RETURN' }
    ]},

    // GENERIC //

    NfGenMessage: { root: true, kind: 'struct', orig: 'nfgenmsg', docs: [
        'General form of address family dependent message.'
    ], attrs: [
        [ 'family',  u8, { orig: 'nfgen_family' } ],
        [ 'version', u8, { orig: 'nfgen_version' } ],
        [ 'res_id', u16, { orig: 'nfgen_res_id' } ]
    ]},

    // TABLES //
    NfTableAttributes: { kind: 'struct', orig: 'nfgenmsg', docs: [
        'Attributes used in Table Messages'
    ], attrs: [
        [ 'name',   string, { orig: 'nfgen_name' } ],
        [ 'flags',  u32,    { orig: 'nfgen_flags' } ],
        [ 'use',    u32,    { orig: 'nfgen_use' } ],
        [ 'handle', u64,    { orig: 'nfgen_handle' } ],
        [ 'pad5',   u32,    { orig: 'nfgen_pad5' } ],
        [ 'user',   string, { orig: 'nfgen_user' } ],
        [ 'owner',  u32,    { orig: 'nfgen_owner' } ]    
    ]},

    TableFlags: { kind: 'flags', orig: 'nft_table_flags', docs: [
        'f_tables table flags',
        'NFT_TABLE_F_DORMANT: this table is not active'
        ], values: [
            { value: 1 << 0, name: 'DORMANT', orig: 'NFT_TABLE_F_DORMANT' },
            { value: 1 << 1, name: 'OWNER',   orig: 'NFT_TABLE_F_OWNER' }
    ]},

    // CHAINS //
    HookNum: { kind: 'enum', orig: 'nf_inet_hooks', docs: [
        'Netfilter hook numbers.'
    ], values: [
        { value: 0, name: 'PREROUTING', orig: 'NF_INET_PRE_ROUTING' },
        { value: 1, name: 'INPUT',      orig: 'NF_INET_LOCAL_IN' },
        { value: 2, name: 'FORWARD',    orig: 'NF_INET_FORWARD' },
        { value: 3, name: 'OUTPUT',     orig: 'NF_INET_LOCAL_OUT' },
        { value: 4, name: 'POSTROUTING',orig: 'NF_INET_POST_ROUTING'},
        { value: 5, name: 'INGRESS',    orig: 'NF_INET_INGRESS' }
    ]},

    NetDevHookNum: { kind: 'enum', orig: 'nf_inet_dev_hooks', docs: [
        'Netfilter device hook numbers.'
    ], values: [
        { value: 0, name: 'INGRESS',    orig: 'NF_NETDEV_INGRESS' },
        { value: 1, name: 'EGRESS', orig: 'NF_NETDEV_INGRESS' }
    ]},

    ArpHookNum: { kind: 'enum', orig: 'nf_arp_hooks', docs: [
        'Netfilter ARP hook numbers.'
    ], values: [
        { value: 0, name: 'APR_IN',      orig: 'NF_ARP_IN' },
        { value: 1, name: 'ARP_OUT',     orig: 'NF_ARP_OUT' },
        { value: 2, name: 'ARP_FORWARD', orig: 'NF_ARP_FORWARD' }
    ]},

    Devices: { kind: 'struct', orig: '', docs: [
        'Netfilter device name array.'
    ], attrs : [
        [ 'name', string, { orig: 'nfta_device_name' } ]
    ]},

    Hook: { kind: 'struct', orig: '', docs: [
        'Netfilter hook attributes.'
    ], attrs: [
        [ 'hooknum',  u32,    { orig: 'nfta_hooknum' } ],
        [ 'priority', u32,    { orig: 'nfta_priority' } ],
        [ 'dev',      string, { orig: 'nfta_dev' } ],
        [ 'devices',  string, { orig: 'nfta_devices' } ] // Nested fix me
    ]},

    ChainCounters: { kind: 'struct', orig: '', docs: [
        'Netfilter chain counters.'
    ], attrs: [
        [ 'bytes',   u64, { orig: 'nfta_counter_bytes' } ],
        [ 'packets', u64, { orig: 'nfta_counter_packets' } ]
    ]},

    ChainAttributes: { kind: 'struct', orig: '', docs: [
        'Netfilter chain attributes.'
    ], attrs: [
        [ 'table',    string,          { orig: 'nfta_table' } ],
        [ 'handle',   u64,             { orig: 'nfta_handle' } ],
        [ 'name',     string,          { orig: 'nfta_name' } ],
        [ 'hook',     u8, { type: 'Hook', orig: 'nfta_hook', docs: [
            "Find documenation for this and update me",
        ] }],
        [ 'policy',   u32,             { orig: 'nfta_policy' } ],
        [ 'use',      u32,             { orig: 'nfta_use' } ],
        [ 'counters', u8, { type: 'ChainCounters', orig: 'nfta_counters', docs: [
            "Find documenation for this and update me",
        ] }],
        [ 'pad9',     string,          { orig: 'nfta_pad9' } ],
        [ 'flags',    u32,             { orig: 'nfta_flags' } ],
        [ 'chain_id', u32,             { orig: 'nfta_chain_id' } ],
        [ 'user',     string,          { orig: 'nfta_user' } ]
    ]},
}

types