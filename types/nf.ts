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
        { value:  0, name: 'NONE',                  orig: 'NFNLGRP_NONE' },
        { value:  1, name: 'CONNTRACK_NEW',         orig: 'NFNLGRP_CONNTRACK_NEW' },
        { value:  2, name: 'CONNTRACK_UPDATE',      orig: 'NFNLGRP_CONNTRACK_UPDATE' },
        { value:  3, name: 'CONNTRACK_DESTROY',     orig: 'NFNLGRP_CONNTRACK_DESTROY' },
        { value:  4, name: 'CONNTRACK_EXP_NEW',     orig: 'NFNLGRP_CONNTRACK_EXP_NEW' },
        { value:  5, name: 'CONNTRACK_EXP_UPDATE',  orig: 'NFNLGRP_CONNTRACK_EXP_UPDATE' },
        { value:  6, name: 'CONNTRACK_EXP_DESTROY', orig: 'NFNLGRP_CONNTRACK_EXP_DESTROY' },
        { value:  7, name: 'NFTABLES',              orig: 'NFNLGRP_NFTABLES' },
        { value:  8, name: 'ACCT_QUOTA',            orig: 'NFNLGRP_ACCT_QUOTA' },
        { value:  9, name: 'NFTRACE',               orig: 'NFNLGRP_NFTRACE' }
    ]},

    // TABLES //

    NfGenMessage: { root: true, kind: 'struct', orig: 'nfgenmsg', docs: [
        'General form of address family dependent message.'
    ], attrs: [
        [ 'family',  u8, { orig: 'nfgen_family' } ],
        [ 'version', u8, { orig: 'nfgen_version' } ],
        [ 'res_id', u16, { orig: 'nfgen_res_id' } ]
    ]},

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
    ]}
}

types