/* packet-awdl.c
 * Apple Wireless Direct Link (AWDL) protocol packet disassembly
 *
 * Copyright 2017 David Kreitschmann <dkreitschmann@seemoo.tu-darmstadt.de>
 * Copyright 2018 Milan Stute <mstute@seemoo.tu-darmstadt.de>
 *
 * Released as part of:
 *   Milan Stute, David Kreitschmann, and Matthias Hollick. "One Billion Apples'
 *   Secret Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol"
 *   in ACM MobiCom '18. https://doi.org/10.1145/3241539.3241566
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-llc.h>
#include <epan/dissectors/packet-ieee80211.h>
#include <epan/dissectors/packet-dns.h>
#include <epan/oui.h>
#include <glib.h>
#include "packet-awdl.h"

#define LLC_PID_AWDL 0x0800

static const unit_name_string units_ieee80211_tu = { " TU", NULL }; /* 1 TU = 1024 microseconds */

static int proto_awdl = -1;
static int proto_awdl_data = -1;

static int hf_awdl_unknown = -1;

static int hf_awdl_fixed_parameters = -1;
static int hf_awdl_tagged_parameters = -1;

static int hf_awdl_data_seq = -1;
static int hf_awdl_data_header = -1;
static int hf_awdl_data_ethertype = -1;

static int hf_awdl_type = -1;
static int hf_awdl_subtype = -1;
static int hf_awdl_rsvd = -1;
static int hf_awdl_phytime = -1;
static int hf_awdl_targettime = -1;
static int hf_awdl_txdelay = -1;

static int hf_awdl_tag = -1;
static int hf_awdl_tag_number = -1;
static int hf_awdl_tag_length = -1;
static int hf_awdl_tag_data = -1;
static int hf_awdl_tag_padding = -1;

static int hf_awdl_version = -1;
static int hf_awdl_version_minor = -1;
static int hf_awdl_version_major = -1;
static int hf_awdl_version_devclass = -1;

static int hf_awdl_datastate_flags = -1;
static int hf_awdl_datastate_flags_0 = -1;
static int hf_awdl_datastate_flags_1 = -1;
static int hf_awdl_datastate_flags_2 = -1;
static int hf_awdl_datastate_flags_3 = -1;
static int hf_awdl_datastate_flags_4 = -1;
static int hf_awdl_datastate_flags_5 = -1;
static int hf_awdl_datastate_flags_6 = -1;
static int hf_awdl_datastate_flags_7 = -1;
static int hf_awdl_datastate_flags_8 = -1;
static int hf_awdl_datastate_flags_9 = -1;
static int hf_awdl_datastate_flags_10 = -1;
static int hf_awdl_datastate_flags_11 = -1;
static int hf_awdl_datastate_flags_12 = -1;
static int hf_awdl_datastate_flags_13 = -1;
static int hf_awdl_datastate_flags_14 = -1;
static int hf_awdl_datastate_flags_15 = -1;
static int hf_awdl_datastate_extflags = -1;
static int hf_awdl_datastate_extflags_0 = -1;
static int hf_awdl_datastate_extflags_1 = -1;
static int hf_awdl_datastate_extflags_2 = -1;
static int hf_awdl_datastate_extflags_3to15 = -1;
static int hf_awdl_datastate_infra_channel = -1;
static int hf_awdl_datastate_countrycode = -1;
static int hf_awdl_datastate_social_channel = -1;
static int hf_awdl_datastate_social_channel_map = -1;
static int hf_awdl_datastate_social_channel_map_6 = -1;
static int hf_awdl_datastate_social_channel_map_44 = -1;
static int hf_awdl_datastate_social_channel_map_149 = -1;
static int hf_awdl_datastate_social_channel_map_unused = -1;
static int hf_awdl_datastate_infra_bssid = -1;
static int hf_awdl_datastate_infra_address = -1;
static int hf_awdl_datastate_awdl_address = -1;
static int hf_awdl_datastate_umi = -1;
static int hf_awdl_datastate_umioptions = -1;
static int hf_awdl_datastate_umioptions_length = -1;
static int hf_awdl_datastate_logtrigger = -1;
static int hf_awdl_datastate_undecoded = -1;

static int hf_awdl_synctree_addr = -1;

static int hf_awdl_syncparams_master = -1;
static int hf_awdl_syncparams_awcounter = -1;
static int hf_awdl_syncparams_apbeaconalignment = -1;
static int hf_awdl_syncparams_tx_chan = -1;
static int hf_awdl_syncparams_tx_counter = -1;
static int hf_awdl_syncparams_master_chan = -1;
static int hf_awdl_syncparams_guard_time = -1;
static int hf_awdl_syncparams_aw_period = -1;
static int hf_awdl_syncparams_action_frame_period = -1;
static int hf_awdl_syncparams_awdl_flags = -1;
static int hf_awdl_syncparams_aw_ext_length = -1;
static int hf_awdl_syncparams_aw_cmn_length = -1;
static int hf_awdl_syncparams_aw_remaining = -1;
static int hf_awdl_syncparams_ext_min = -1;
static int hf_awdl_syncparams_ext_max_multi = -1;
static int hf_awdl_syncparams_ext_max_uni = -1;
static int hf_awdl_syncparams_ext_max_af = -1;
static int hf_awdl_syncparams_presence_mode = -1;

static int hf_awdl_channelseq_enc = -1;
static int hf_awdl_channelseq_duplicate = -1;
static int hf_awdl_channelseq_step_count = -1;
static int hf_awdl_channelseq_fill_chan = -1;
static int hf_awdl_channelseq_channel_count = -1;
static int hf_awdl_channelseq_channel_list = -1;
static int hf_awdl_channelseq_channel = -1;
static int hf_awdl_channelseq_channel_number = -1;
static int hf_awdl_channelseq_channel_flags = -1;
static int hf_awdl_channelseq_channel_operating_class = -1;
/* legacy encoding flags */
static int hf_awdl_channelseq_legacy_unused = -1;
static int hf_awdl_channelseq_legacy_band = -1;
static int hf_awdl_channelseq_legacy_bandwidth = -1;
static int hf_awdl_channelseq_legacy_control_channel = -1;

static int hf_awdl_electionparams_master = -1;
static int hf_awdl_electionparams_flags = -1;
static int hf_awdl_electionparams_id = -1;
static int hf_awdl_electionparams_distance = -1;
static int hf_awdl_electionparams_mastermetric = -1;
static int hf_awdl_electionparams_selfmetric = -1;
static int hf_awdl_electionparams_unknown = -1;
static int hf_awdl_electionparams_private_master = -1;
static int hf_awdl_electionparams_private_mastermetric = -1;
static int hf_awdl_electionparams_private_id = -1;
static int hf_awdl_electionparams_private_phc = -1;
static int hf_awdl_electionparams_private_unknown = -1;

static int hf_awdl_electionparams2_master = -1;
static int hf_awdl_electionparams2_other = -1;
static int hf_awdl_electionparams2_mastermetric = -1;
static int hf_awdl_electionparams2_selfmetric = -1;
static int hf_awdl_electionparams2_mastercounter = -1;
static int hf_awdl_electionparams2_selfcounter = -1;
static int hf_awdl_electionparams2_distance = -1;
static int hf_awdl_electionparams2_unknown = -1;
static int hf_awdl_electionparams2_reserved = -1;

static int hf_awdl_dns_name_len = -1;
static int hf_awdl_dns_name = -1;
static int hf_awdl_dns_name_label = -1;
static int hf_awdl_dns_name_short = -1;
static int hf_awdl_dns_type = -1;
static int hf_awdl_dns_data_len = -1;
static int hf_awdl_dns_txt = -1;
static int hf_awdl_dns_ptr = -1;
static int hf_awdl_dns_ptr_label = -1;
static int hf_awdl_dns_ptr_short = -1;
static int hf_awdl_dns_target = -1;
static int hf_awdl_dns_target_label = -1;
static int hf_awdl_dns_target_short = -1;
static int hf_awdl_dns_unknown = -1;
static int hf_awdl_dns_priority = -1;
static int hf_awdl_dns_weight = -1;
static int hf_awdl_dns_port = -1;

static int hf_awdl_serviceparams_sui = -1;
static int hf_awdl_serviceparams_enc_values = -1;
static int hf_awdl_serviceparams_bitmask = -1;
static int hf_awdl_serviceparams_bitmask_0 = -1;
static int hf_awdl_serviceparams_bitmask_1 = -1;
static int hf_awdl_serviceparams_bitmask_2 = -1;
static int hf_awdl_serviceparams_bitmask_3 = -1;
static int hf_awdl_serviceparams_bitmask_4 = -1;
static int hf_awdl_serviceparams_bitmask_5 = -1;
static int hf_awdl_serviceparams_bitmask_6 = -1;
static int hf_awdl_serviceparams_bitmask_7 = -1;
static int hf_awdl_serviceparams_bitmask_8 = -1;
static int hf_awdl_serviceparams_bitmask_9 = -1;
static int hf_awdl_serviceparams_bitmask_10 = -1;
static int hf_awdl_serviceparams_bitmask_11 = -1;
static int hf_awdl_serviceparams_bitmask_12= -1;
static int hf_awdl_serviceparams_bitmask_13 = -1;
static int hf_awdl_serviceparams_bitmask_14 = -1;
static int hf_awdl_serviceparams_bitmask_15 = -1;
static int hf_awdl_serviceparams_bitmask_16 = -1;
static int hf_awdl_serviceparams_bitmask_17 = -1;
static int hf_awdl_serviceparams_bitmask_18 = -1;
static int hf_awdl_serviceparams_bitmask_19 = -1;
static int hf_awdl_serviceparams_bitmask_20 = -1;
static int hf_awdl_serviceparams_bitmask_21 = -1;
static int hf_awdl_serviceparams_bitmask_22 = -1;
static int hf_awdl_serviceparams_bitmask_23 = -1;
static int hf_awdl_serviceparams_bitmask_24 = -1;
static int hf_awdl_serviceparams_bitmask_25 = -1;
static int hf_awdl_serviceparams_bitmask_26 = -1;
static int hf_awdl_serviceparams_bitmask_27 = -1;
static int hf_awdl_serviceparams_bitmask_28 = -1;
static int hf_awdl_serviceparams_bitmask_29 = -1;
static int hf_awdl_serviceparams_bitmask_30 = -1;
static int hf_awdl_serviceparams_bitmask_31 = -1;
static int hf_awdl_serviceparams_values = -1;
static int hf_awdl_serviceparams_values_0 = -1;
static int hf_awdl_serviceparams_values_1 = -1;
static int hf_awdl_serviceparams_values_2 = -1;
static int hf_awdl_serviceparams_values_3 = -1;
static int hf_awdl_serviceparams_values_4 = -1;
static int hf_awdl_serviceparams_values_5 = -1;
static int hf_awdl_serviceparams_values_6 = -1;
static int hf_awdl_serviceparams_values_7 = -1;

static int hf_awdl_arpa = -1;
static int hf_awdl_arpa_flags = -1;
static int hf_awdl_arpa_name = -1;
static int hf_awdl_arpa_short = -1;

static int hf_awdl_ht_unknown = -1;
/* from hf_ieee80211_* from packet-ieee80211.c */
static int hf_ieee80211_ht_cap = -1;
static int hf_ieee80211_ht_ldpc_coding = -1;
static int hf_ieee80211_ht_chan_width = -1;
static int hf_ieee80211_ht_sm_pwsave = -1;
static int hf_ieee80211_ht_green = -1;
static int hf_ieee80211_ht_short20 = -1;
static int hf_ieee80211_ht_short40 = -1;
static int hf_ieee80211_ht_tx_stbc = -1;
static int hf_ieee80211_ht_rx_stbc = -1;
static int hf_ieee80211_ht_delayed_block_ack = -1;
static int hf_ieee80211_ht_max_amsdu = -1;
static int hf_ieee80211_ht_dss_cck_40 = -1;
static int hf_ieee80211_ht_psmp = -1;
static int hf_ieee80211_ht_40_mhz_intolerant = -1;
static int hf_ieee80211_ht_l_sig = -1;
static int hf_ieee80211_ampduparam = -1;
static int hf_ieee80211_ampduparam_mpdu = -1;
static int hf_ieee80211_ampduparam_mpdu_start_spacing = -1;
static int hf_ieee80211_ampduparam_reserved = -1;
static int hf_ieee80211_mcsset = -1;
static int hf_ieee80211_mcsset_rx_bitmask = -1;
static int hf_ieee80211_mcsset_rx_bitmask_0to7 = -1;
static int hf_ieee80211_mcsset_rx_bitmask_8to15 = -1;
static int hf_ieee80211_mcsset_rx_bitmask_16to23 = -1;
static int hf_ieee80211_mcsset_rx_bitmask_24to31 = -1;

static int hf_llc_apple_pid = -1;

static gint ett_awdl_data = -1;
static gint ett_awdl = -1;
static gint ett_awdl_fixed_parameters = -1;
static gint ett_awdl_tagged_parameters = -1;
static gint ett_awdl_unknown = -1;
static gint ett_awdl_tag = -1;
static gint ett_awdl_channelseq_flags = -1;
static gint ett_awdl_version = -1;
static gint ett_awdl_dns_record = -1;
static gint ett_awdl_dns_name = -1;
static gint ett_awdl_channelseq_channel_list = -1;
static gint ett_awdl_channelseq_channel = -1;
static gint ett_awdl_datastate_flags = -1;
static gint ett_awdl_datastate_social_channel_map = -1;
static gint ett_awdl_datastate_extflags = -1;
static gint ett_ieee80211_ht_capabilities = -1;
static gint ett_ieee80211_ht_ampduparam = -1;
static gint ett_ieee80211_ht_mcsset_tree = -1;
static gint ett_ieee80211_ht_mcsbit_tree = -1;
static gint ett_awdl_serviceparams_bitmask = -1;
static gint ett_awdl_serviceparams_values = -1;
static gint ett_awdl_serviceparams_value = -1;

static expert_field ei_awdl_tag_length = EI_INIT;
static expert_field ei_awdl_tag_data = EI_INIT;

static dissector_table_t ethertype_subdissector_table;
static dissector_table_t tagged_field_table;

enum tag_length {
  TAG_LENGTH_SHORT = 2, /* short tag tag length, used in legacy data frames */
  TAG_LENGTH       = 3, /* normal tag header length */
};

enum {
  AWDL_SSTH_REQUEST_TLV = 0,
  AWDL_SERVICE_REQUEST_TLV = 1,
  AWDL_SERVICE_RESPONSE_TLV = 2,
  AWDL_UNKNOWN_3_TLV = 3,
  AWDL_SYNCHRONIZATON_PARAMETERS_TLV = 4,
  AWDL_ELECTION_PARAMETERS_TLV = 5,
  AWDL_SERVICE_PARAMETERS_TLV = 6,
  AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV = 7,
  AWDL_ENHANCED_DATA_RATE_OPERATION_TLV = 8,
  AWDL_INFRA_TLV = 9,
  AWDL_INVITE_TLV = 10,
  AWDL_DBG_STRING_TLV = 11,
  AWDL_DATA_PATH_STATE_TLV = 12,
  AWDL_ENCAPSULATED_IP_TLV = 13,
  AWDL_DATAPATH_DEBUG_PACKET_LIVE_TLV = 14,
  AWDL_DATAPATH_DEBUG_AF_LIVE_TLV = 15,
  AWDL_ARPA_TLV = 16,
  AWDL_IEEE80211_CONTAINER_TLV = 17,
  AWDL_CHAN_SEQ_TLV = 18,
  AWDL_UNKNOWN_19_TLV = 19,
  AWDL_SYNCHRONIZATION_TREE_TLV = 20,
  AWDL_VERSION_TLV = 21,
  AWDL_BLOOM_FILTER_TLV = 22,
  AWDL_NAN_SYNC_TLV = 23,
  AWDL_ELECTION_PARAMETERS_V2_TLV = 24,
};

static const value_string tag_num_vals[] = {
  { AWDL_SSTH_REQUEST_TLV, "SSTH Request" },
  { AWDL_SERVICE_REQUEST_TLV, "Service Request" },
  { AWDL_SERVICE_RESPONSE_TLV, "Service Response" },
  { AWDL_UNKNOWN_3_TLV, "Unknown" },
  { AWDL_SYNCHRONIZATON_PARAMETERS_TLV, "Synchronization Parameters" },
  { AWDL_ELECTION_PARAMETERS_TLV, "Election Parameters" },
  { AWDL_SERVICE_PARAMETERS_TLV, "Service Parameters" },
  { AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV, "HT Capabilities (IEEE 802.11 subset)" },
  { AWDL_ENHANCED_DATA_RATE_OPERATION_TLV, "Enhanced Data Rate Operation" },
  { AWDL_INFRA_TLV, "Infra" },
  { AWDL_INVITE_TLV, "Invite" },
  { AWDL_DBG_STRING_TLV, "Debug String" },
  { AWDL_DATA_PATH_STATE_TLV, "Data Path State" },
  { AWDL_ENCAPSULATED_IP_TLV, "Encapsulated IP" },
  { AWDL_DATAPATH_DEBUG_PACKET_LIVE_TLV, "Datapath Debug Packet Live" },
  { AWDL_DATAPATH_DEBUG_AF_LIVE_TLV, "Datapath Debug AF Live" },
  { AWDL_ARPA_TLV, "Arpa" },
  { AWDL_IEEE80211_CONTAINER_TLV, "IEEE 802.11 Container" },
  { AWDL_CHAN_SEQ_TLV, "Channel Sequence" },
  { AWDL_UNKNOWN_19_TLV, "Unknown" },
  { AWDL_SYNCHRONIZATION_TREE_TLV, "Synchronization Tree" },
  { AWDL_VERSION_TLV, "Version" },
  { AWDL_BLOOM_FILTER_TLV, "Bloom Filter" },
  { AWDL_NAN_SYNC_TLV, "NAN Sync" },
  { AWDL_ELECTION_PARAMETERS_V2_TLV, "Election Parameters v2" },
  { 0, NULL }
};
static value_string_ext tag_num_vals_ext = VALUE_STRING_EXT_INIT(tag_num_vals);

static const value_string awdl_type[] = {
  { 8, "AWDL" },
  { 0, NULL }
};

enum {
  AWDL_SUBTYPE_PSF = 0,
  AWDL_SUBTYPE_MIF = 3
};

static const value_string awdl_subtype[] = {
  { AWDL_SUBTYPE_PSF, "Periodic Synchronization Frame (PSF)" },
  { AWDL_SUBTYPE_MIF, "Master Indication Frame (MIF)" },
  { 0, NULL }
};

static const value_string awdl_subtype_col[] = {
  { AWDL_SUBTYPE_PSF, "Periodic Synchronization" },
  { AWDL_SUBTYPE_MIF, "Master Indication" },
  { 0, NULL }
};

static const value_string awdl_subtype_short[] = {
  { AWDL_SUBTYPE_PSF, "PSF" },
  { AWDL_SUBTYPE_MIF, "MIF" },
  { 0, NULL }
};

enum {
  AWDL_CHANSEQ_ENC_CHANNELNUMBER = 0,
  AWDL_CHANSEQ_ENC_LEGACY = 1,
  AWDL_CHANSEQ_ENC_OPCLASS = 3,
};

static const value_string awdl_chanseq_enc[] = {
  { AWDL_CHANSEQ_ENC_CHANNELNUMBER, "Channelnumber" },
  { AWDL_CHANSEQ_ENC_LEGACY, "Legacy" },
  { AWDL_CHANSEQ_ENC_OPCLASS, "Opclass" },
  { 0, NULL }
};

static const value_string awdl_chanseq_control_channel[] = {
  { 1, "Lower" },
  { 2, "Upper" },
  { 3, "Primary" },
  { 0, NULL }
};

static const value_string awdl_chanseq_bandwidth[] = {
  { 1, "20 MHz" },
  { 3, "40 MHz" },
  { 0, NULL }
};

static const value_string awdl_chanseq_band[] = {
  { 2, "2.4 GHz" },
  { 1, "5 GHz" },
  { 0, NULL }
};

static const value_string awdl_chanseq_fill_chan[] = {
  { 0xffff, "Repeat Current" },
  { 0, NULL }
};

enum {
  AWDL_VERSION_MACOS = 1,
  AWDL_VERSION_IOS = 2,
  AWDL_VERSION_TVOS = 8,
};

static const value_string awdl_version_devclass[] = {
  { AWDL_VERSION_MACOS, "macOS" },
  { AWDL_VERSION_IOS, "iOS or watchOS" },
  { AWDL_VERSION_TVOS, "tvOS" },
  { 0, NULL }
};

static const value_string apple_pid_vals[] = {
  { LLC_PID_AWDL, "AWDL" },
  { 0,            NULL }
};

enum {
  T_PTR = 12, /* domain name pointer */
  T_TXT = 16, /* text strings */
  T_SRV = 33, /* service location (RFC 2052) */
};

static const value_string dns_types_vals[] = {
  { T_PTR, "PTR" },
  { T_TXT, "TXT" },
  { T_SRV, "SRV" }, /* RFC 2052 */
  { 0,     NULL }
};

static const value_string awdl_dns_compression[] = {
  { 0xC000, "NULL" },
  { 0xC001, "_airplay._tcp.local" },
  { 0xC002, "_airplay._udp.local" },
  { 0xC003, "_airplay" },
  { 0xC004, "_raop._tcp.local" },
  { 0xC005, "_raop._udp.local" },
  { 0xC006, "_raop" },
  { 0xC007, "_airdrop._tcp.local" },
  { 0xC008, "_airdrop._udp.local" },
  { 0xC009, "_airdrop" },
  { 0xC00A, "_tcp.local" },
  { 0xC00B, "_udp.local" },
  { 0xC00C, "local" },
  { 0xC00D, "ip6.arpa" },
  { 0xC00E, "ip4.arpa" },
  { 0,      NULL }
};

/* from packet-ieee80211.c */
static const true_false_string ht_ldpc_coding_flag = {
  "Transmitter supports receiving LDPC coded packets",
  "Transmitter does not support receiving LDPC coded packets"
};

/* from packet-ieee80211.c */
static const true_false_string ht_chan_width_flag = {
  "Transmitter supports 20MHz and 40MHz operation",
  "Transmitter only supports 20MHz operation"
};

/* from packet-ieee80211.c */
static const value_string ht_sm_pwsave_flag[] = {
  { 0x00, "Static SM Power Save mode" },
  { 0x01, "Dynamic SM Power Save mode" },
  { 0x02, "Reserved" },
  { 0x03, "SM Power Save disabled" },
  { 0x00, NULL}
};

/* from packet-ieee80211.c */
static const true_false_string ht_green_flag = {
  "Transmitter is able to receive PPDUs with Green Field (GF) preamble",
  "Transmitter is not able to receive PPDUs with Green Field (GF) preamble"
};

/* from packet-ieee80211.c */
static const value_string ht_rx_stbc_flag[] = {
  {0x00, "No Rx STBC support"},
  {0x01, "Rx support of one spatial stream"},
  {0x02, "Rx support of one and two spatial streams"},
  {0x03, "Rx support of one, two, and three spatial streams"},
  {0x00, NULL}
};

/* from packet-ieee80211.c */
static const true_false_string ht_delayed_block_ack_flag = {
  "Transmitter supports HT-Delayed BlockAck",
  "Transmitter does not support HT-Delayed BlockAck"
};

/* from packet-ieee80211.c */
static const true_false_string ht_max_amsdu_flag = {
  "7935 bytes",
  "3839 bytes"
};

/* from packet-ieee80211.c */
static const true_false_string ht_dss_cck_40_flag = {
  "Will/Can use DSSS/CCK in 40 MHz",
  "Won't/Can't use of DSSS/CCK in 40 MHz"
};

/* from packet-ieee80211.c */
static const true_false_string ht_psmp_flag = {
  "Will/Can support PSMP operation",
  "Won't/Can't support PSMP operation"
};

/* from packet-ieee80211.c */
static const true_false_string ht_40_mhz_intolerant_flag = {
  "Use of 40 MHz transmissions restricted/disallowed",
  "Use of 40 MHz transmissions unrestricted/allowed"
};

/* from packet-ieee80211.c */
static const value_string ampduparam_mpdu_start_spacing_flags[] = {
  {0x00, "no restriction"},
  {0x01, "1/4 [usec]"},
  {0x02, "1/2 [usec]"},
  {0x03, "1 [usec]"},
  {0x04, "2 [usec]"},
  {0x05, "4 [usec]"},
  {0x06, "8 [usec]"},
  {0x07, "16 [usec]"},
  {0x00, NULL}
};

/* from packet-ieee80211.c */
static const value_string mcsset_tx_max_spatial_streams_flags[] = {
  { 0x00, "1 spatial stream" },
  { 0x01, "2 spatial streams" },
  { 0x02, "3 spatial streams" },
  { 0x03, "4 spatial streams" },
  { 0x04, "TX MCS Set Not Defined" },
  { 0x00, NULL}
};

static proto_item *
add_awdl_version(tvbuff_t *tvb, int offset, proto_tree *tree) {
  proto_item *version_item;
  guint64 version;
  static const int *fields[] = {
    &hf_awdl_version_major,
    &hf_awdl_version_minor,
    NULL
  };

  version_item = proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_awdl_version, ett_awdl_version,
                                                              fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND, &version);
  proto_item_append_text(version_item, " (%lu.%lu)", (version >> 4) & 0xf, version & 0xf);

  return version_item;
}

static int
awdl_tag_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;

  add_awdl_version(tvb, offset, tree);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_version_devclass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}

static int
awdl_tag_sync_tree(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int tag_len = tvb_reported_length(tvb);
  int offset = 0;

  for (; offset <= tag_len - 6; offset += 6) {
    proto_tree_add_item(tree, hf_awdl_synctree_addr, tvb, offset, 6, ENC_NA);
  }

  return offset;
}

inline static gboolean
test_bit_guint32(guint i, guint32 n) {
  return ((n >> i) & 1) == 1;
}

static int
awdl_tag_service_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  proto_item *values_item, *offset_item;
  proto_tree *values_tree;
  int offset = 0;

  static const int *bitmask_fields[] = {
    &hf_awdl_serviceparams_bitmask_0,
    &hf_awdl_serviceparams_bitmask_1,
    &hf_awdl_serviceparams_bitmask_2,
    &hf_awdl_serviceparams_bitmask_3,
    &hf_awdl_serviceparams_bitmask_4,
    &hf_awdl_serviceparams_bitmask_5,
    &hf_awdl_serviceparams_bitmask_6,
    &hf_awdl_serviceparams_bitmask_7,
    &hf_awdl_serviceparams_bitmask_8,
    &hf_awdl_serviceparams_bitmask_9,
    &hf_awdl_serviceparams_bitmask_10,
    &hf_awdl_serviceparams_bitmask_11,
    &hf_awdl_serviceparams_bitmask_12,
    &hf_awdl_serviceparams_bitmask_13,
    &hf_awdl_serviceparams_bitmask_14,
    &hf_awdl_serviceparams_bitmask_15,
    &hf_awdl_serviceparams_bitmask_16,
    &hf_awdl_serviceparams_bitmask_17,
    &hf_awdl_serviceparams_bitmask_18,
    &hf_awdl_serviceparams_bitmask_19,
    &hf_awdl_serviceparams_bitmask_20,
    &hf_awdl_serviceparams_bitmask_21,
    &hf_awdl_serviceparams_bitmask_22,
    &hf_awdl_serviceparams_bitmask_23,
    &hf_awdl_serviceparams_bitmask_24,
    &hf_awdl_serviceparams_bitmask_25,
    &hf_awdl_serviceparams_bitmask_26,
    &hf_awdl_serviceparams_bitmask_27,
    &hf_awdl_serviceparams_bitmask_28,
    &hf_awdl_serviceparams_bitmask_29,
    &hf_awdl_serviceparams_bitmask_30,
    &hf_awdl_serviceparams_bitmask_31,
    NULL
  };

  static const int *value_fields[] = {
    &hf_awdl_serviceparams_values_0,
    &hf_awdl_serviceparams_values_1,
    &hf_awdl_serviceparams_values_2,
    &hf_awdl_serviceparams_values_3,
    &hf_awdl_serviceparams_values_4,
    &hf_awdl_serviceparams_values_5,
    &hf_awdl_serviceparams_values_6,
    &hf_awdl_serviceparams_values_7,
    NULL
  };

  proto_tree_add_item(tree, hf_awdl_unknown, tvb, offset, 3, ENC_NA);
  offset += 3;
  proto_tree_add_item(tree, hf_awdl_serviceparams_sui, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  values_item = proto_tree_add_item(tree, hf_awdl_serviceparams_enc_values, tvb, offset, 0, ENC_NA); /* set length later */
  values_tree = proto_item_add_subtree(values_item, ett_awdl_serviceparams_values);

  offset_item = proto_tree_add_bitmask_with_flags(values_tree, tvb, offset, hf_awdl_serviceparams_bitmask, ett_awdl_serviceparams_bitmask, bitmask_fields, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
  guint32 bitmask = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
  offset += 4;

  if (bitmask != 0) {
    guint count = 0;
    for (guint i = 0; i < 32; i++) {
      if (test_bit_guint32(i, bitmask)) {
        proto_item *value_item;
        guint shift = i << 3;
        value_item = proto_tree_add_bitmask(values_tree, tvb, offset, hf_awdl_serviceparams_values,
                               ett_awdl_serviceparams_value, value_fields, ENC_LITTLE_ENDIAN);
        guint8 value = tvb_get_guint8(tvb, offset);
        for (guint k = 0; k < 8; k++) {
          if (test_bit_guint32(k, value)) {
            if (count == 0) {
              proto_item_append_text(values_item, ": %u", k + shift);
            } else {
              proto_item_append_text(values_item, ", %u", k + shift);
            }
            count++;
          }
        }
        proto_item_append_text(offset_item, ", %u", shift);
        proto_item_append_text(value_item, " (offset %u)", shift);
        offset++;
      }
    }
    proto_item_set_end(values_item, tvb, offset);
  }

  return offset;
}

static int
awdl_tag_channel_sequence(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  proto_item *chanlist_item, *channel_item;
  proto_tree *chanlist_tree, *channel_tree;
  guint channels, chan_number;
  wmem_strbuf_t *strbuf;
  int offset = 0;

  static const int *flags_fields[] = {
    &hf_awdl_channelseq_legacy_control_channel,
    &hf_awdl_channelseq_legacy_bandwidth,
    &hf_awdl_channelseq_legacy_band,
    &hf_awdl_channelseq_legacy_unused,
    NULL
  };

  proto_tree_add_item_ret_uint(tree, hf_awdl_channelseq_channel_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &channels);
  channels += 1; /* channel list length is +1 */
  offset += 1;

  guint8 seq_enc = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_awdl_channelseq_enc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_channelseq_duplicate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_channelseq_step_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_channelseq_fill_chan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  /* make sufficient space for channel decodings: 5 chars/channel (3-digit number + ', ') */
  strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), 5 * channels, 5 * channels);

  switch (seq_enc) {
  case AWDL_CHANSEQ_ENC_CHANNELNUMBER:
    chanlist_item = proto_tree_add_item(tree, hf_awdl_channelseq_channel_list, tvb, offset, channels, ENC_NA);
    chanlist_tree = proto_item_add_subtree(chanlist_item, ett_awdl_channelseq_channel_list);
    for (guint i = 0; i < channels; i++) {
      proto_tree_add_item_ret_uint(chanlist_tree, hf_awdl_channelseq_channel_number, tvb, offset, 1, ENC_LITTLE_ENDIAN, &chan_number);
      offset += 1;

      if (i != 0) {
        /* not the first */
        wmem_strbuf_append_printf(strbuf, ", %u", chan_number);
      } else {
        wmem_strbuf_append_printf(strbuf, "%u", chan_number);
      }
    }
    break;
  case AWDL_CHANSEQ_ENC_LEGACY:
    chanlist_item = proto_tree_add_item(tree, hf_awdl_channelseq_channel_list, tvb, offset, 2 * channels, ENC_NA);
    chanlist_tree = proto_item_add_subtree(chanlist_item, ett_awdl_channelseq_channel_list);
    for (guint i = 0; i < channels; i++) {
      chan_number = tvb_get_guint8(tvb, offset + 1);
      channel_item = proto_tree_add_uint(chanlist_tree, hf_awdl_channelseq_channel, tvb, offset, 2, chan_number);
      channel_tree = proto_item_add_subtree(channel_item, ett_awdl_channelseq_channel);
      proto_tree_add_bitmask(channel_tree, tvb, offset, hf_awdl_channelseq_channel_flags,
                             ett_awdl_channelseq_flags, flags_fields, ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(channel_tree, hf_awdl_channelseq_channel_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;

      if (i != 0) {
        /* not the first */
        wmem_strbuf_append_printf(strbuf, ", %u", chan_number);
      } else {
        wmem_strbuf_append_printf(strbuf, "%u", chan_number);
      }
    }
    break;
  case AWDL_CHANSEQ_ENC_OPCLASS:
    chanlist_item = proto_tree_add_item(tree, hf_awdl_channelseq_channel_list, tvb, offset, 2 * channels, ENC_NA);
    chanlist_tree = proto_item_add_subtree(chanlist_item, ett_awdl_channelseq_channel_list);
    for (guint i = 0; i < channels; i++) {
      chan_number = tvb_get_guint8(tvb, offset);
      channel_item = proto_tree_add_uint(chanlist_tree, hf_awdl_channelseq_channel, tvb, offset, 2, chan_number);
      channel_tree = proto_item_add_subtree(channel_item, ett_awdl_channelseq_channel);
      proto_tree_add_item(channel_tree, hf_awdl_channelseq_channel_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(channel_tree, hf_awdl_channelseq_channel_operating_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;

      if (i != 0) {
        /* not the first */
        wmem_strbuf_append_printf(strbuf, ", %u", chan_number);
      } else {
        wmem_strbuf_append_printf(strbuf, "%u", chan_number);
      }
    }
    break;
  default:
    /* TODO error handling */
    chanlist_item = NULL;
    break;
  }

  if (chanlist_item) {
    /* finally, append channel list as string */
    proto_item_append_text(chanlist_item, ": %s", wmem_strbuf_get_str(strbuf));
  }

  return offset;
}

static int
awdl_tag_sync_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int tag_len = tvb_reported_length(tvb);
  tvbuff_t *chanseq_tvb;
  int offset = 0;

  proto_tree_add_item(tree, hf_awdl_syncparams_tx_chan, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_tx_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_master_chan, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_guard_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_aw_period, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_action_frame_period, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_awdl_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_aw_ext_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_aw_cmn_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_aw_remaining, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_ext_min, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_ext_max_multi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_ext_max_uni, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_ext_max_af, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  //the following values are also used in IOFamily
  proto_tree_add_item(tree, hf_awdl_syncparams_master, tvb, offset, 6, ENC_NA);
  offset += 6;
  proto_tree_add_item(tree, hf_awdl_syncparams_presence_mode, tvb, offset, 1, ENC_NA);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_unknown, tvb, offset, 1, ENC_NA);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_syncparams_awcounter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_syncparams_apbeaconalignment, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  chanseq_tvb = tvb_new_subset_length(tvb, offset, tag_len - offset);
  offset += awdl_tag_channel_sequence(chanseq_tvb, pinfo, tree, data);

  return offset;
}

static int
awdl_tag_election_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;

  guint8 private_election = tvb_get_guint8(tvb, offset);

  proto_tree_add_item(tree, hf_awdl_electionparams_flags, tvb, offset, 1, ENC_NA);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_electionparams_id, tvb, offset, 2, ENC_NA);
  offset += 2;
  proto_tree_add_item(tree, hf_awdl_electionparams_distance, tvb, offset, 1, ENC_NA);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_electionparams_unknown, tvb, offset, 1, ENC_NA);
  offset += 1;
  proto_tree_add_item(tree, hf_awdl_electionparams_master, tvb, offset, 6, ENC_NA);
  offset += 6;
  proto_tree_add_item(tree, hf_awdl_electionparams_mastermetric, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams_selfmetric, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  if (private_election) {
    proto_tree_add_item(tree, hf_awdl_unknown, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_awdl_electionparams_private_master, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(tree, hf_awdl_electionparams_private_mastermetric, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_awdl_electionparams_private_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_awdl_electionparams_private_phc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
  }

  return offset;
}

static int
awdl_tag_election_params_v2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;

  proto_tree_add_item(tree, hf_awdl_electionparams2_master, tvb, offset, 6, ENC_NA);
  offset += 6;
  proto_tree_add_item(tree, hf_awdl_electionparams2_other, tvb, offset, 6, ENC_NA);
  offset += 6;
  proto_tree_add_item(tree, hf_awdl_electionparams2_mastercounter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_distance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_mastermetric, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_selfmetric, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_unknown, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_awdl_electionparams2_selfcounter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset;
}

static int
awdl_tag_datapath_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  guint16 flags;

  static const int *flags_fields[] = {
    &hf_awdl_datastate_flags_0,
    &hf_awdl_datastate_flags_1,
    &hf_awdl_datastate_flags_2,
    &hf_awdl_datastate_flags_3,
    &hf_awdl_datastate_flags_4,
    &hf_awdl_datastate_flags_5,
    &hf_awdl_datastate_flags_6,
    &hf_awdl_datastate_flags_7,
    &hf_awdl_datastate_flags_8,
    &hf_awdl_datastate_flags_9,
    &hf_awdl_datastate_flags_10,
    &hf_awdl_datastate_flags_11,
    &hf_awdl_datastate_flags_12,
    &hf_awdl_datastate_flags_13,
    &hf_awdl_datastate_flags_14,
    &hf_awdl_datastate_flags_15,
    NULL
  };

  static const int *channel_map_fields[] = {
    &hf_awdl_datastate_social_channel_map_6,
    &hf_awdl_datastate_social_channel_map_44,
    &hf_awdl_datastate_social_channel_map_149,
    &hf_awdl_datastate_social_channel_map_unused,
    NULL
  };

  static const int *extflags_fields[] = {
    &hf_awdl_datastate_extflags_0,
    &hf_awdl_datastate_extflags_1,
    &hf_awdl_datastate_extflags_2,
    &hf_awdl_datastate_extflags_3to15,
    NULL
  };

  flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
  proto_tree_add_bitmask(tree, tvb, offset, hf_awdl_datastate_flags,
                         ett_awdl_datastate_flags, flags_fields, ENC_LITTLE_ENDIAN);
  offset += 2;

  if (flags & 0x0100) {
    proto_tree_add_item(tree, hf_awdl_datastate_countrycode, tvb, offset, 3, ENC_NA);
    offset += 3;
  }
  if (flags & 0x0200) {
    /* this can either be a channel or a map indicating which channels this node supports */
    guint16 map = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    /* TODO unverified heuristic to decide whether this is a map or number */
    if (map & 1) {
      proto_tree_add_bitmask(tree, tvb, offset, hf_awdl_datastate_social_channel_map,
                             ett_awdl_datastate_social_channel_map, channel_map_fields, ENC_LITTLE_ENDIAN);
    } else {
      /* a single channel number */
      proto_tree_add_item(tree, hf_awdl_datastate_social_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;
  }
  if (flags & 0x0001) {
    proto_tree_add_item(tree, hf_awdl_datastate_infra_bssid, tvb, offset, 6, ENC_NA);
    proto_tree_add_item(tree, hf_awdl_datastate_infra_channel, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);
    offset += 8;
  }
  if (flags & 0x0002) {
    // if not set, this will be the same as 0x1
    proto_tree_add_item(tree, hf_awdl_datastate_infra_address, tvb, offset, 6, ENC_NA);
    offset += 6;
  }
  if (flags & 0x0004) {
    proto_tree_add_item(tree, hf_awdl_datastate_awdl_address, tvb, offset, 6, ENC_NA);
    offset += 6;
  }
  if (flags & 0x0010) {
    proto_tree_add_item(tree, hf_awdl_datastate_umi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
  }
  if (flags & 0x1000) {
    guint16 optionlength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_awdl_datastate_umioptions_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_awdl_datastate_umioptions, tvb, offset, optionlength, ENC_LITTLE_ENDIAN);
    offset += optionlength;
  }
  /* now come the extended parameters */
  if (flags & 0x8000) {
    guint16 extflags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset, hf_awdl_datastate_extflags,
                           ett_awdl_datastate_extflags, extflags_fields, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (extflags & 0x4) {
      proto_tree_add_item(tree, hf_awdl_datastate_logtrigger, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;
    }
    if (extflags & 0x1) {
      /* TODO add actual fields
       *
       * Binary: IO80211Family
       * Method: IO80211AWDLPeer::parseAwdlDataPathTLVAndTakeAction
       *
       * __cstring:0000000000091E2A aRlfc           db 'RLFC',0
       * __cstring:0000000000091E2F aMsecsince      db 'msecSince',0
       * __cstring:0000000000091E39 aAwseq          db 'awSeq',0
       * __cstring:0000000000091E3F aPayupdatecount db 'payUpdateCounter',0
       */
      proto_tree_add_item(tree, hf_awdl_datastate_undecoded, tvb, offset, 14, ENC_NA);
      offset += 14;
    }
  }

  return offset;
}

static int
awdl_tag_ieee80211_container(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  int offset = 0;

  const guint8 ids[] = {
    191, // VHT Capability
  };
  offset += add_tagged_field(pinfo, tree, tvb, offset, MGT_ACTION, ids, G_N_ELEMENTS(ids), NULL);

  return offset;
}

static int
awdl_tag_ht_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  proto_item *ti, *cap_item;
  proto_tree *mcs_tree, *bit_tree, *cap_tree;
  guint8 streams; /* 0-4 for HT and 0-8 for VHT*/
  int offset = 0;
  int tag_len = tvb_reported_length(tvb);

  static const int *ieee80211_ht[] = {
    &hf_ieee80211_ht_ldpc_coding,
    &hf_ieee80211_ht_chan_width,
    &hf_ieee80211_ht_sm_pwsave,
    &hf_ieee80211_ht_green,
    &hf_ieee80211_ht_short20,
    &hf_ieee80211_ht_short40,
    &hf_ieee80211_ht_tx_stbc,
    &hf_ieee80211_ht_rx_stbc,
    &hf_ieee80211_ht_delayed_block_ack,
    &hf_ieee80211_ht_max_amsdu,
    &hf_ieee80211_ht_dss_cck_40,
    &hf_ieee80211_ht_psmp,
    &hf_ieee80211_ht_40_mhz_intolerant,
    &hf_ieee80211_ht_l_sig,
    NULL
  };

  proto_tree_add_item(tree, hf_awdl_ht_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ieee80211_ht_cap, ett_ieee80211_ht_capabilities,
                                    ieee80211_ht, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
  offset += 2;

  cap_item = proto_tree_add_item(tree, hf_ieee80211_ampduparam, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  cap_tree = proto_item_add_subtree(cap_item, ett_ieee80211_ht_ampduparam);
  ti = proto_tree_add_item(cap_tree, hf_ieee80211_ampduparam_mpdu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  proto_item_append_text(ti, " (%04.0f[Bytes])", pow(2, 13 + (tvb_get_guint8(tvb, offset) & 0x3)) - 1);
  proto_tree_add_item(cap_tree, hf_ieee80211_ampduparam_mpdu_start_spacing, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(cap_tree, hf_ieee80211_ampduparam_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  /* Check how many streams are supported */
  for (streams = 0; streams < 4 /* max streams */ && tvb_get_guint8(tvb, offset + streams) != 0; streams++) {
  }

  ti = proto_tree_add_item(tree, hf_ieee80211_mcsset, tvb, offset, streams, ENC_NA);
  mcs_tree = proto_item_add_subtree(ti, ett_ieee80211_ht_mcsset_tree);

  /* Rx MCS Bitmask */
  ti = proto_tree_add_item(mcs_tree, hf_ieee80211_mcsset_rx_bitmask, tvb, offset, streams, ENC_NA);
  bit_tree = proto_item_add_subtree(ti, ett_ieee80211_ht_mcsbit_tree);

  proto_tree_add_item(bit_tree, hf_ieee80211_mcsset_rx_bitmask_0to7, tvb, offset, streams, ENC_LITTLE_ENDIAN);
  offset += 1;
  if (offset < tag_len - 2) {
    proto_tree_add_item(bit_tree, hf_ieee80211_mcsset_rx_bitmask_8to15, tvb, offset - 1, streams, ENC_LITTLE_ENDIAN);
    offset += 1;
  }
  if (offset < tag_len - 2) {
    proto_tree_add_item(bit_tree, hf_ieee80211_mcsset_rx_bitmask_16to23, tvb, offset - 2, streams, ENC_LITTLE_ENDIAN);
    offset += 1;
  }
  if (offset < tag_len - 2) {
    proto_tree_add_item(bit_tree, hf_ieee80211_mcsset_rx_bitmask_24to31, tvb, offset - 3, streams, ENC_LITTLE_ENDIAN);
    offset += 1;
  }

  proto_item_append_text(ti, ": %s", val_to_str(streams - 1, mcsset_tx_max_spatial_streams_flags, "Reserved: %d" ) );

  // Some padding at the end
  proto_tree_add_item(tree, hf_awdl_ht_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  return offset;
}

/*
 * Decodes a AWDL-variant DNS name.
 *
 * 'hfindex_regular' needs to registered as
 * 'hfindex_compressed' assumes a field that can be decoded with the 'awdl_dns_compression' value_string
 */
static int
add_awdl_dns_name(proto_tree *tree, int hfindex_regular, int hfindex_compressed,
                  tvbuff_t *tvb, int offset, int len, const gchar **name) {
  int start_offset = offset;
  guint8 component_len;
  const guchar *component;
  wmem_strbuf_t *strbuf;

  strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), MAXDNAME, MAXDNAME);

  while (offset < (len + start_offset)) {
    component_len = tvb_get_guint8(tvb, offset);
    if (component_len & 0xC0) {
      /* compressed label */
      guint compressed_value;
      proto_tree_add_item_ret_uint(tree, hfindex_compressed, tvb, offset, 2, ENC_BIG_ENDIAN, &compressed_value);
      if (compressed_value == 0xC000) {
        // 'NULL' compression -> ignore in printed string
        component = NULL;
      } else {
        component = val_to_str_const(compressed_value, awdl_dns_compression, "<UNKNOWN>");
      }
      offset += 2;
    } else {
      /* regular label */
      guint label_len;
      proto_tree_add_item_ret_string_and_length(tree, hfindex_regular, tvb, offset, 1, ENC_ASCII, wmem_packet_scope(), &component, &label_len);
      offset += label_len;
    }
    if (component) {
      if (wmem_strbuf_get_len(strbuf))
        /* not the first entry */
        wmem_strbuf_append_c(strbuf, '.');
      wmem_strbuf_append(strbuf, component);
    }
  }

  *name = wmem_strbuf_get_str(strbuf);

  return offset - start_offset;
}

static int
add_awdl_dns_entry(proto_tree *tree, gint ett,
                   int hfindex_entry, int hfindex_regular, int hfindex_compressed,
                   tvbuff_t *tvb, int offset, int len, const gchar **name) {
  int start_offset = offset;
  proto_item *entry_item;
  proto_tree *entry_tree;
  const gchar *n;

  entry_item = proto_tree_add_item(tree, hfindex_entry, tvb, offset, 0, ENC_NA);
  entry_tree = proto_item_add_subtree(entry_item, ett);
  offset += add_awdl_dns_name(entry_tree, hfindex_regular, hfindex_compressed, tvb, offset, len, &n);
  proto_item_set_end(entry_item, tvb, offset);
  proto_item_append_text(entry_item, ": %s", n);

  if (name)
    (*name) = n;

  return offset - start_offset;
}

static int
awdl_tag_arpa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  int tag_len = tvb_reported_length(tvb);

  proto_tree_add_item(tree, hf_awdl_arpa_flags, tvb, offset, 1, ENC_NA);
  offset += 1;
  offset += add_awdl_dns_entry(tree, ett_awdl_dns_name, hf_awdl_arpa, hf_awdl_arpa_name,
                               hf_awdl_arpa_short, tvb, offset, tag_len - offset, NULL);

  return offset;
}

static int
awdl_tag_service_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  proto_item *rr_item;
  proto_tree *rr_tree;
  const gchar *name;
  int offset = 0;
  guint len, type;
  guint prio, weight, port;

  rr_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_awdl_dns_record, &rr_item, "");

  proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_name_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
  offset += 2;

  // len field includes the following type value
  len -= 1;
  offset += add_awdl_dns_entry(rr_tree, ett_awdl_dns_name, hf_awdl_dns_name, hf_awdl_dns_name_label,
                               hf_awdl_dns_name_short, tvb, offset, len, &name);

  proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &type);
  offset += 1;

  proto_item_set_text(rr_item, "%s: type %s", name, val_to_str_const(type, dns_types_vals, "UNKNOWN"));

  proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_data_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
  offset += 2;
  // TODO could be that len field is actually uint32?
  proto_tree_add_item(rr_tree, hf_awdl_dns_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  switch (type) {
  case T_TXT:
    while (len > 0) {
      const guchar *txt;
      gint label_len;
      proto_tree_add_item_ret_string_and_length(rr_tree, hf_awdl_dns_txt, tvb, offset, 1, ENC_ASCII,
                                                wmem_packet_scope(), &txt, &label_len);
      offset += label_len;
      len -= label_len;
      proto_item_append_text(rr_item, ", %s", txt);
    }
    break;
  case T_SRV:
    proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_priority, tvb, offset, 2, ENC_BIG_ENDIAN, &prio);
    offset += 2;
    proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_weight, tvb, offset, 2, ENC_BIG_ENDIAN, &weight);
    offset += 2;
    proto_tree_add_item_ret_uint(rr_tree, hf_awdl_dns_port, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;
    // length field includes above fields
    len -= 6;
    offset += add_awdl_dns_entry(rr_tree, ett_awdl_dns_name, hf_awdl_dns_target, hf_awdl_dns_target_label,
                                 hf_awdl_dns_target_short, tvb, offset, len, &name);
    proto_item_append_text(rr_item, ", priority %u, weight %u, port %u, target %s", prio, weight, port, name);
    break;
  case T_PTR:
    offset += add_awdl_dns_entry(rr_tree, ett_awdl_dns_name, hf_awdl_dns_ptr, hf_awdl_dns_ptr_label,
                                 hf_awdl_dns_ptr_short, tvb, offset, len, &name);
    proto_item_append_text(rr_item, ", %s", name);
    break;
  default:
    break;
  }

  return offset;
}

static int
awdl_add_tagged_field(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, enum tag_length hdr_len) {
  tvbuff_t     *tag_tvb;
  guint32       tag_no, tag_len;
  proto_tree   *orig_tree = tree;
  proto_item   *ti        = NULL;
  proto_item   *ti_len, *ti_tag;
  awdl_tagged_field_data_t field_data;
  int parsed;

  tag_no = tvb_get_guint8(tvb, offset);
  if (hdr_len == TAG_LENGTH_SHORT) {
    tag_len = tvb_get_guint8(tvb, offset + 1);
  } else {
    tag_len = tvb_get_guint16(tvb, offset + 1, ENC_LITTLE_ENDIAN);
  }

  if (tree) {
    ti = proto_tree_add_item(orig_tree, hf_awdl_tag, tvb, offset, tag_len + hdr_len, ENC_NA);
    proto_item_append_text(ti, ": %s", val_to_str_ext(tag_no, &tag_num_vals_ext, "Unknown (%d)"));
    tree = proto_item_add_subtree(ti, ett_awdl_tag);
  }

  ti_tag = proto_tree_add_uint(tree, hf_awdl_tag_number, tvb, offset, 1, tag_no);
  ti_len = proto_tree_add_uint(tree, hf_awdl_tag_length, tvb, offset + 1, hdr_len - 1, tag_len);
  offset += hdr_len;
  if (tag_len > (guint)tvb_reported_length_remaining(tvb, offset)) {
    expert_add_info_format(pinfo, ti_len, &ei_awdl_tag_length,
                           "Tag Length is longer than remaining payload");
  }

  tag_tvb = tvb_new_subset_length(tvb, offset, tag_len);
  field_data.item_tag = ti;
  field_data.item_tag_length = ti_len;
  if (!(parsed = dissector_try_uint_new(tagged_field_table, tag_no, tag_tvb, pinfo, tree, FALSE, &field_data)))
  {
    proto_tree_add_item(tree, hf_awdl_tag_data, tag_tvb, 0, tag_len, ENC_NA);
    expert_add_info_format(pinfo, ti_tag, &ei_awdl_tag_data,
                           "Dissector for AWDL tag (%s) code not implemented",
                           val_to_str_ext(tag_no, &tag_num_vals_ext, "(%d)"));
    proto_item_append_text(ti, ": Undecoded");
  }
  else if (parsed > 0 && (unsigned int) parsed < tag_len)
  {
    proto_tree_add_item(tree, hf_awdl_tag_padding, tag_tvb, parsed, tag_len - parsed, ENC_NA);
  }

  return tag_len + hdr_len;
}

static void
awdl_add_tagged_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int tagged_parameters_len)
{
  int next_len;
  while (tagged_parameters_len > 0) {
    if ((next_len = awdl_add_tagged_field(pinfo, tree, tvb, offset, TAG_LENGTH)) == 0)
      break;
    if (next_len > tagged_parameters_len) {
      /* XXX - flag this as an error? */
      next_len = tagged_parameters_len;
    }
    offset                += next_len;
    tagged_parameters_len -= next_len;
  }
}

static proto_tree *
get_tagged_parameter_tree(proto_tree * tree, tvbuff_t *tvb, int start, int size)
{
  proto_item *tagged_fields;

  tagged_fields = proto_tree_add_item(tree, hf_awdl_tagged_parameters, tvb, start, -1, ENC_NA);
  proto_item_append_text(tagged_fields, " (%d bytes)", size);

  return proto_item_add_subtree(tagged_fields, ett_awdl_tagged_parameters);
}

int dissect_awdl_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int        offset = 0;
  gint       tagged_parameter_tree_len;
  proto_tree *parent, *af_tree, *fixed_tree, *tag_tree;
  proto_item *ti, *item, *fixed_fields;
  guint32 phytime, targettime;
  guint8 subtype;

  parent = proto_tree_get_parent_tree(proto_tree_get_parent_tree(tree));
  ti = proto_tree_add_item(parent, proto_awdl, tvb, offset, -1, ENC_NA);
  af_tree = proto_item_add_subtree(ti, ett_awdl);

  fixed_fields = proto_tree_add_item(af_tree, hf_awdl_fixed_parameters, tvb, offset, 12, ENC_NA);
  fixed_tree =  proto_item_add_subtree(fixed_fields, ett_awdl_fixed_parameters);
  proto_tree_add_item(fixed_tree, hf_awdl_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  add_awdl_version(tvb, offset, fixed_tree);
  offset += 1;
  subtype = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(fixed_tree, hf_awdl_subtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(fixed_tree, hf_awdl_rsvd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(fixed_tree, hf_awdl_phytime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  phytime = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(fixed_tree, hf_awdl_targettime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  targettime = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
  offset += 4;
  item = proto_tree_add_uint(fixed_tree, hf_awdl_txdelay, tvb, 0, 0, phytime - targettime);
  PROTO_ITEM_SET_GENERATED(item);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AWDL");
  col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(subtype, awdl_subtype_col, "Unknown"));
  proto_item_append_text(ti, ", Subtype: %s", val_to_str_const(subtype, awdl_subtype_short, "Unknown"));

  tagged_parameter_tree_len = tvb_reported_length_remaining(tvb, offset);
  tag_tree = get_tagged_parameter_tree(af_tree, tvb, offset, tagged_parameter_tree_len);
  awdl_add_tagged_parameters(tvb, offset, pinfo, tag_tree, tagged_parameter_tree_len);
  offset += tagged_parameter_tree_len;

  return offset;
}

int dissect_awdl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  gint      offset = 0;
  guint     etype;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AWDL Data");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti;
    proto_tree *awdl_tree;
    guint seq;

    ti = proto_tree_add_item(tree, proto_awdl_data, tvb, 0, -1, ENC_NA);

    awdl_tree = proto_item_add_subtree(ti, ett_awdl_data);

    proto_tree_add_item(awdl_tree, hf_awdl_data_header, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item_ret_uint(awdl_tree, hf_awdl_data_seq, tvb, offset, 2, ENC_LITTLE_ENDIAN, &seq);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u", seq);
    proto_item_append_text(ti, ", Seq: %u", seq);
    offset += 2;

     if (tvb_get_guint8(tvb, offset) == 3) {
       // 0x0300 ("long format")
       proto_item *tagged_item;
       proto_tree *tagged_tree;
       int         start_offset;
       guint8      slen;

       slen = tvb_get_guint8(tvb, offset + 1);
       proto_tree_add_item(awdl_tree, hf_awdl_data_header, tvb, offset, 2 + slen, ENC_NA);
       offset += 2 + slen;

       tagged_item = proto_tree_add_item(awdl_tree, hf_awdl_tagged_parameters, tvb, offset, 0, ENC_NA); /* set length later */
       tagged_tree = proto_item_add_subtree(tagged_item, ett_awdl_tagged_parameters);

       start_offset = offset;

       while (tvb_get_guint8(tvb, offset) != 3) {
         offset += awdl_add_tagged_field(pinfo, tagged_tree, tvb, offset, TAG_LENGTH_SHORT);
       }

       slen = tvb_get_guint8(tvb, offset + 1);
       proto_tree_add_item(awdl_tree, hf_awdl_data_header, tvb, offset, 2 + slen, ENC_NA);
       offset += 2 + slen;

       proto_item_set_len(tagged_item, offset - start_offset);
       proto_item_append_text(tagged_item, " (%d bytes)", offset - start_offset);

     } else {
      // 0x0000
      // TODO: should have some sanity check.
      proto_tree_add_item(awdl_tree, hf_awdl_data_header, tvb, offset, 2, ENC_NA);
      offset += 2;
    }

    /* Last is some ethertype */
    proto_tree_add_item_ret_uint(awdl_tree, hf_awdl_data_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN, &etype);
    offset += 2;

    proto_item_set_len(awdl_tree, offset);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint(ethertype_subdissector_table, etype, next_tvb, pinfo, tree))
      call_data_dissector(next_tvb, pinfo, tree);
  }
  return tvb_captured_length(tvb);
}

static void
awdl_register_tags(void)
{
  dissector_add_uint("awdl.tag.number", AWDL_SERVICE_RESPONSE_TLV, create_dissector_handle(awdl_tag_service_response, -1));
  dissector_add_uint("awdl.tag.number", AWDL_SYNCHRONIZATON_PARAMETERS_TLV, create_dissector_handle(awdl_tag_sync_params, -1));
  dissector_add_uint("awdl.tag.number", AWDL_ELECTION_PARAMETERS_TLV, create_dissector_handle(awdl_tag_election_params, -1));
  dissector_add_uint("awdl.tag.number", AWDL_SERVICE_PARAMETERS_TLV, create_dissector_handle(awdl_tag_service_params, -1));
  dissector_add_uint("awdl.tag.number", AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV, create_dissector_handle(awdl_tag_ht_capabilities, -1));
  dissector_add_uint("awdl.tag.number", AWDL_DATA_PATH_STATE_TLV, create_dissector_handle(awdl_tag_datapath_state, -1));
  dissector_add_uint("awdl.tag.number", AWDL_ARPA_TLV, create_dissector_handle(awdl_tag_arpa, -1));
  dissector_add_uint("awdl.tag.number", AWDL_IEEE80211_CONTAINER_TLV, create_dissector_handle(awdl_tag_ieee80211_container, -1));
  dissector_add_uint("awdl.tag.number", AWDL_CHAN_SEQ_TLV, create_dissector_handle(awdl_tag_channel_sequence, -1));
  dissector_add_uint("awdl.tag.number", AWDL_SYNCHRONIZATION_TREE_TLV, create_dissector_handle(awdl_tag_sync_tree, -1));
  dissector_add_uint("awdl.tag.number", AWDL_VERSION_TLV, create_dissector_handle(awdl_tag_version, -1));
  dissector_add_uint("awdl.tag.number", AWDL_ELECTION_PARAMETERS_V2_TLV, create_dissector_handle(awdl_tag_election_params_v2, -1));
}

void proto_register_awdl(void)
{
  static hf_register_info hf[] = {
    /* Default for unknown fields */
    { &hf_awdl_unknown,
      { "Unknown", "awdl.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },

    /* LLC */
    { &hf_awdl_data_seq,
      { "Sequence number", "awdl_data.seq",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_data_header,
      { "Header data", "awdl_data.header",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_data_ethertype,
      { "EtherType", "awdl_data.ethertype",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
      }
    },

    /* Action Frame */
    { &hf_awdl_fixed_parameters,
      { "Fixed parameters", "awdl.fixed.all",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_tagged_parameters,
      { "Tagged parameters", "awdl.tagged.all",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },

    /* Fixed parameters */
    { &hf_awdl_type,
      { "Type", "awdl.type",
        FT_UINT8, BASE_DEC, VALS(awdl_type), 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_subtype,
      { "Subtype", "awdl.subtype",
        FT_UINT8, BASE_DEC, VALS(awdl_subtype), 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_rsvd,
      { "Reserved", "awdl.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_phytime,
      { "PHY Tx Time", "awdl.phytime",
        FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_microseconds, 0x0,
        "Time shortly before the frame was sent out by the radio", HFILL
      }
    },
    { &hf_awdl_targettime,
      { "Target Tx Time", "awdl.targettime",
        FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_microseconds, 0x0,
        "Time when the frame was created.", HFILL
      }
    },
    { &hf_awdl_txdelay,
      { "Tx Delay", "awdl.txdelay",
        FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_microseconds, 0x0,
        "Difference between the PHY and target time stamps", HFILL
      }
    },

    /* TLV */
    { &hf_awdl_tag,
      { "Tag", "awdl.tag",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_tag_number,
      { "Tag Number", "awdl.tag.number",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &tag_num_vals_ext, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_tag_length,
      { "Tag Length", "awdl.tag.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_tag_data,
      { "Tag Data", "awdl.tag.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Data Interpretation of tag", HFILL
      }
    },
    { &hf_awdl_tag_padding,
      { "Padding (?)", "awdl.tag.padding",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Unused (?) bytes at the end of the tag", HFILL
      }
    },

    /* Version */
    { &hf_awdl_version,
      { "AWDL Version", "awdl.version",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_version_major,
      { "AWDL Version Major", "awdl.version.major",
        FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL
      }
    },
    { &hf_awdl_version_minor,
      { "AWDL Version Minor", "awdl.version.minor",
        FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL
      }
    },
    { &hf_awdl_version_devclass,
      { "Device Class", "awdl.version.device_class",
        FT_UINT8, BASE_DEC, VALS(awdl_version_devclass), 0, NULL, HFILL
      }
    },

    /* Synchronization Tree */
    { &hf_awdl_synctree_addr,
      { "Address", "awdl.synctree.addr",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        "From tree root to leaf", HFILL
      }
    },

    /* Data Path State */
    { &hf_awdl_datastate_flags,
      { "Flags", "awdl.datastate.flags",
        FT_UINT16, BASE_HEX, NULL, 0,
        "Subsequent fields do not follow the order in which they appear in this bitmask", HFILL
      }
    },
    { &hf_awdl_datastate_flags_0,
      { "Infrastructure BSSID and Channel", "awdl.datastate.flags.0",
        FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_1,
      { "Infrastructure Address", "awdl.datastate.flags.1",
        FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_2,
      { "AWDL Address", "awdl.datastate.flags.2",
        FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_3,
      { "Bit 3", "awdl.datastate.flags.3",
        FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_4,
      { "UMI", "awdl.datastate.flags.4",
        FT_BOOLEAN, 16, NULL, 0x10, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_5,
      { "Bit 5", "awdl.datastate.flags.5",
        FT_BOOLEAN, 16, NULL, 0x20, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_6,
      { "Is AirPlay (?)", "awdl.datastate.flags.6",
        FT_BOOLEAN, 16, NULL, 0x40, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_7,
      { "Bit 6", "awdl.datastate.flags.7",
        FT_BOOLEAN, 16, NULL, 0x80, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_8,
      { "Country Code", "awdl.datastate.flags.8",
        FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_9,
      { "Social Channels", "awdl.datastate.flags.9",
        FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_10,
      { "Bit 10", "awdl.datastate.flags.10",
        FT_BOOLEAN, 16, NULL, 0x400, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_11,
      { "Bit 11", "awdl.datastate.flags.11",
        FT_BOOLEAN, 16, NULL, 0x800, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_12,
      { "Unicast Options", "awdl.datastate.flags.12",
        FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_13,
      { "Bit 13", "awdl.datastate.flags.13",
        FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_14,
      { "Is Rangeable", "awdl.datastate.flags.14",
        FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_flags_15,
      { "Extension Flags", "awdl.datastate.flags.15",
        FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_countrycode,
      { "Country Code", "awdl.datastate.countrycode",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel,
      { "Social Channel", "awdl.datastate.social_channel",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel_map,
      { "Social Channel Map", "awdl.datastate.social_channel_map",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel_map_6,
      { "Channel 6", "awdl.datastate.social_channel_map.ch6",
        FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel_map_44,
      { "Channel 44", "awdl.datastate.social_channel_map.ch44",
        FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel_map_149,
      { "Channel 149", "awdl.datastate.social_channel_map.ch149",
        FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_social_channel_map_unused,
      { "Unused", "awdl.datastate.social_channel_map.unused",
        FT_UINT16, BASE_HEX, NULL, 0xfff8, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_infra_bssid,
      { "Infrastructure BSSID", "awdl.datastate.infra_bssid",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        "Address of the AP currently connected to", HFILL
      }
    },
    { &hf_awdl_datastate_infra_channel,
      { "Infrastructure Channel", "awdl.datastate.infra_channel",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_infra_address,
      { "Infrastructure Address", "awdl.datastate.infra_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        "MAC address of this device", HFILL
      }
    },
    { &hf_awdl_datastate_awdl_address,
      { "AWDL Address", "awdl.datastate.own_awdladdr",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        "Randomized Address used for AWDL", HFILL
      }
    },
    { &hf_awdl_datastate_umi,
      { "UMI (Airplay?)", "awdl.datastate.umi",
        FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_umioptions,
      { "Unicast Options", "awdl.datastate.unicast_options",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_umioptions_length,
      { "Unicast Options Length", "awdl.datastate.unicast_options_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_extflags,
      { "Extended Flags", "awdl.datastate.extflags",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_extflags_0,
      { "Undecoded (?)", "awdl.datastate.extflags.0",
        FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_extflags_1,
      { "Ranging Discovery", "awdl.datastate.extflags.1",
        FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_extflags_2,
      { "Logtrigger ID", "awdl.datastate.extflags.2",
        FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_extflags_3to15,
      { "Unknown", "awdl.datastate.extflags.3to15",
        FT_UINT16, BASE_HEX_DEC, NULL, 0xfff8, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_logtrigger,
      { "Logtrigger ID", "awdl.datastate.logtrigger",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_datastate_undecoded,
      { "Undecoded", "awdl.datastate.undecoded",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Possibly contains 'RLFC', a timestamp in ms, a AW sequence number, and 'payUpdateCounter'", HFILL
      }
    },

    /* Arpa */
    { &hf_awdl_arpa,
      { "Arpa", "awdl.arpa",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_arpa_name,
      { "Host", "awdl.arpa.host",
        FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_arpa_flags,
      { "Flags", "awdl.arpa.flags",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_arpa_short,
      { "Domain (compressed)", "awdl.arpa.domain",
        FT_UINT16, BASE_HEX, VALS(awdl_dns_compression), 0, NULL, HFILL
      }
    },

    /* Synchronization Paramters */
    { &hf_awdl_syncparams_awcounter,
      { "AW Sequence Number", "awdl.syncparams.awseqcounter",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_apbeaconalignment,
      { "AP Beacon alignment delta", "awdl.syncparams.apbeaconalignment",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_master,
      { "Master Address", "awdl.syncparams.master",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_tx_chan,
      { "Next AW Channel", "awdl.syncparams.txchannel",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_tx_counter,
      { "Tx Counter", "awdl.syncparams.txcounter",
        FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0,
        "Time until next AW starts", HFILL
      }
    },
    { &hf_awdl_syncparams_master_chan,
      { "Master Channel", "awdl.syncparams.masterchan",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_guard_time,
      { "Guard Time", "awdl.syncparams.guardtime",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_aw_period,
      { "Availability Window Period", "awdl.syncparams.awperiod",
        FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_action_frame_period,
      { "Action Frame Period", "awdl.syncparams.afperiod",
        FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_awdl_flags,
      { "AWDL Flags", "awdl.syncparams.awdlflags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_aw_ext_length,
      { "Availability Window Extension Length", "awdl.syncparams.aw.ext_len",
        FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_aw_cmn_length,
      { "Availability Window Common Length", "awdl.syncparams.aw.common_len",
        FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_aw_remaining,
      { "Remaining Availability Window Length", "awdl.syncparams.aw.remaining",
        FT_INT16, BASE_DEC | BASE_UNIT_STRING, &units_ieee80211_tu, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_ext_min,
      { "Minimum Extension Count", "awdl.syncparams.ext.min",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_ext_max_multi,
      { "Maximum Extension Count for Multicast", "awdl.syncparams.ext.max_multicast",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_ext_max_uni,
      { "Maximum Extension Count for Unicast", "awdl.syncparams.ext.max_unicast",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_ext_max_af,
      { "Maximum Extension Count for Action Frame", "awdl.syncparams.ext.max_af",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_syncparams_presence_mode,
      { "Presence Mode", "awdl.syncparams.presencemode",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },

    /* Channel Sequence */
    { &hf_awdl_channelseq_channel_count,
      { "Number of Channels (+1)", "awdl.channelseq.channels",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_enc,
      { "Encoding", "awdl.channelseq.encoding",
        FT_UINT8, BASE_DEC, VALS(awdl_chanseq_enc), 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_duplicate,
      { "Duplicate", "awdl.channelseq.duplicate",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_step_count,
      { "Step Count (+1)", "awdl.channelseq.step_count",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_fill_chan,
      { "Fill Channel", "awdl.channelseq.fill_channel",
        FT_UINT16, BASE_HEX, VALS(awdl_chanseq_fill_chan), 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_channel_list,
      { "Channel List", "awdl.channelseq.channel_list",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_channel,
      { "Channel", "awdl.channelseq.channel",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_channel_number,
      { "Channel Number", "awdl.channelseq.channel.number",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_channel_operating_class,
      { "Operating Class", "awdl.channelseq.channel.operating_class",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_channel_flags,
      { "Channel Flags", "awdl.channelseq.channel.flags",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_legacy_unused,
      { "Unused", "awdl.channelseq.channel.unused",
        FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_legacy_band,
      { "Band", "awdl.channelseq.channel.band",
        FT_UINT8, BASE_DEC, VALS(awdl_chanseq_band), 0x30, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_legacy_bandwidth,
      { "Bandwidth", "awdl.channelseq.channel.bandwidth",
        FT_UINT8, BASE_DEC, VALS(awdl_chanseq_bandwidth), 0x0c, NULL, HFILL
      }
    },
    { &hf_awdl_channelseq_legacy_control_channel,
      { "Control Channel", "awdl.channelseq.channel.control_channel",
        FT_UINT8, BASE_DEC, VALS(awdl_chanseq_control_channel), 0x03, NULL, HFILL
      }
    },

    /* Election Parameters */
    { &hf_awdl_electionparams_private_master,
      { "Private Master Address", "awdl.electionparams.private.master",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_master,
      { "Master Address", "awdl.electionparams.master",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_flags,
      { "Flags", "awdl.electionparams.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_id,
      { "ID", "awdl.electionparams.id",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_distance,
      { "Distance to Master", "awdl.electionparams.distance",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_mastermetric,
      { "Master Metric", "awdl.electionparams.mastermetric",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_selfmetric,
      { "Self Metric", "awdl.electionparams.selfmetric",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_unknown,
      { "Unknown", "awdl.electionparams.unknown",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_private_mastermetric,
      { "Private Master Metric", "awdl.electionparams.private.mastermetric",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_private_id,
      { "Private ID", "awdl.electionparams.private.id",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_private_phc,
      { "PHC", "awdl.electionparams.private.phc",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams_private_unknown,
      { "Self Metric", "awdl.electionparams.private.unknown",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },

    /* Election Parameter v2 */
    { &hf_awdl_electionparams2_master,
      { "Master Address", "awdl.electionparams2.master",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_other,
      { "Other Address", "awdl.electionparams2.other",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_mastermetric,
      { "Master Metric", "awdl.electionparams2.mastermetric",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_selfmetric,
      { "Self Metric", "awdl.electionparams2.selfmetric",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_mastercounter,
      { "Master Counter", "awdl.electionparams2.mastercounter",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_selfcounter,
      { "Self Counter", "awdl.electionparams2.selfcounter",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_distance,
      { "Distance to Master", "awdl.electionparams2.disstance",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_reserved,
      { "Reserved", "awdl.electionparams2.reserved",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_electionparams2_unknown,
      { "Unknown", "awdl.electionparams2.unknown",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },

    /* Service Reponse */
    { &hf_awdl_dns_name_len,
      { "Name Length", "awdl.dns.name.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Includes length of type field", HFILL
      }
    },
    { &hf_awdl_dns_name,
      { "Name", "awdl.dns.name",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_name_label,
      { "Label", "awdl.dns.name.label",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Part of a name", HFILL
      }
    },
    { &hf_awdl_dns_name_short,
      { "Label (compressed)", "awdl.dns.name.compressed",
        FT_UINT16, BASE_HEX, VALS(awdl_dns_compression), 0x0,
        "Part of a name", HFILL
      }
    },
    { &hf_awdl_dns_type,
      { "Type", "awdl.dns.type",
        FT_UINT8, BASE_DEC, VALS(dns_types_vals), 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_data_len,
      { "Data Length", "awdl.dns.data_len",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_txt,
      { "TXT", "awdl.dns.txt",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_ptr,
      { "Domain Name", "awdl.dns.ptr",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_ptr_label,
      { "Label", "awdl.dns.ptr.label",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Part of a domain name", HFILL
      }
    },
    { &hf_awdl_dns_ptr_short,
      { "Label (compressed)", "awdl.dns.ptr.short",
        FT_UINT16, BASE_HEX, VALS(awdl_dns_compression), 0x0,
        "Part of a domain name", HFILL
      }
    },
    { &hf_awdl_dns_target,
      { "Target", "awdl.dns.target",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_target_label,
      { "Label", "awdl.dns.target.label",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Part of a target", HFILL
      }
    },
    { &hf_awdl_dns_target_short,
      { "Label (compressed)", "awdl.dns.target.compressed",
        FT_UINT16, BASE_HEX, VALS(awdl_dns_compression), 0x0,
        "Part of a target", HFILL
      }
    },
    { &hf_awdl_dns_unknown,
      { "Unknown", "awdl.dns.unknown",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_priority,
      { "Priority", "awdl.dns.priority",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_weight,
      { "Weight", "awdl.dns.weight",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },
    { &hf_awdl_dns_port,
      { "Port", "awdl.dns.port",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
      }
    },

    /* Service Parameters */
    { &hf_awdl_serviceparams_sui,
      { "SUI", "awdl.serviceparams.sui",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Incremented by 1 for every service announcement change (should cause cache flush at receivers)", HFILL
      }
    },
    { &hf_awdl_serviceparams_enc_values,
      { "Encoded Values", "awdl.serviceparams.valuess",
        FT_NONE, BASE_NONE, NULL, 0,
        "Encodes up to 256 unique 1-byte values. Calculation adds offsets to values.", HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask,
      { "Offsets", "awdl.serviceparams.bitmask",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Offset is 8*i if i-th bit is set", HFILL
      }
    },
    /* Generate with Python
     * size = 32
     * for i in range(size):
     *   print('{{ &hf_awdl_serviceparams_bitmask_{},'.format(i))
     *   print('  {{ "{}", "awdl.serviceparams.bitmask.{}",'.format(i, i))
     *   print('    FT_BOOLEAN, {}, NULL, {}, NULL, HFILL'.format(size, hex(1 << i)))
     *   print('  }}'.format())
     *   print('}},'.format())
     */
    { &hf_awdl_serviceparams_bitmask_0,
      { "0", "awdl.serviceparams.bitmask.0",
        FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_1,
      { "1", "awdl.serviceparams.bitmask.1",
        FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_2,
      { "2", "awdl.serviceparams.bitmask.2",
        FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_3,
      { "3", "awdl.serviceparams.bitmask.3",
        FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_4,
      { "4", "awdl.serviceparams.bitmask.4",
        FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_5,
      { "5", "awdl.serviceparams.bitmask.5",
        FT_BOOLEAN, 32, NULL, 0x20, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_6,
      { "6", "awdl.serviceparams.bitmask.6",
        FT_BOOLEAN, 32, NULL, 0x40, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_7,
      { "7", "awdl.serviceparams.bitmask.7",
        FT_BOOLEAN, 32, NULL, 0x80, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_8,
      { "8", "awdl.serviceparams.bitmask.8",
        FT_BOOLEAN, 32, NULL, 0x100, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_9,
      { "9", "awdl.serviceparams.bitmask.9",
        FT_BOOLEAN, 32, NULL, 0x200, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_10,
      { "10", "awdl.serviceparams.bitmask.10",
        FT_BOOLEAN, 32, NULL, 0x400, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_11,
      { "11", "awdl.serviceparams.bitmask.11",
        FT_BOOLEAN, 32, NULL, 0x800, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_12,
      { "12", "awdl.serviceparams.bitmask.12",
        FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_13,
      { "13", "awdl.serviceparams.bitmask.13",
        FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_14,
      { "14", "awdl.serviceparams.bitmask.14",
        FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_15,
      { "15", "awdl.serviceparams.bitmask.15",
        FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_16,
      { "16", "awdl.serviceparams.bitmask.16",
        FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_17,
      { "17", "awdl.serviceparams.bitmask.17",
        FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_18,
      { "18", "awdl.serviceparams.bitmask.18",
        FT_BOOLEAN, 32, NULL, 0x40000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_19,
      { "19", "awdl.serviceparams.bitmask.19",
        FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_20,
      { "20", "awdl.serviceparams.bitmask.20",
        FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_21,
      { "21", "awdl.serviceparams.bitmask.21",
        FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_22,
      { "22", "awdl.serviceparams.bitmask.22",
        FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_23,
      { "23", "awdl.serviceparams.bitmask.23",
        FT_BOOLEAN, 32, NULL, 0x800000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_24,
      { "24", "awdl.serviceparams.bitmask.24",
        FT_BOOLEAN, 32, NULL, 0x1000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_25,
      { "25", "awdl.serviceparams.bitmask.25",
        FT_BOOLEAN, 32, NULL, 0x2000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_26,
      { "26", "awdl.serviceparams.bitmask.26",
        FT_BOOLEAN, 32, NULL, 0x4000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_27,
      { "27", "awdl.serviceparams.bitmask.27",
        FT_BOOLEAN, 32, NULL, 0x8000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_28,
      { "28", "awdl.serviceparams.bitmask.28",
        FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_29,
      { "29", "awdl.serviceparams.bitmask.29",
        FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_30,
      { "30", "awdl.serviceparams.bitmask.30",
        FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_bitmask_31,
      { "31", "awdl.serviceparams.bitmask.31",
        FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values,
      { "Values", "awdl.serviceparams.values",
        FT_UINT8, BASE_HEX, NULL, 0,
        "Value is i if i-th bit is set", HFILL
      }
    },
    { &hf_awdl_serviceparams_values_0,
      { "0", "awdl.serviceparams.values.0",
        FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_1,
      { "1", "awdl.serviceparams.values.1",
        FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_2,
      { "2", "awdl.serviceparams.values.2",
        FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_3,
      { "3", "awdl.serviceparams.values.3",
        FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_4,
      { "4", "awdl.serviceparams.values.4",
        FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_5,
      { "5", "awdl.serviceparams.values.5",
        FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_6,
      { "6", "awdl.serviceparams.values.6",
        FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL
      }
    },
    { &hf_awdl_serviceparams_values_7,
      { "7", "awdl.serviceparams.values.7",
        FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL
      }
    },

    /* HT Capabilities */
    { &hf_awdl_ht_unknown,
      { "Unknown", "awdl.ht.unknown",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    /* hf_ieee80211_* from packet-ieee80211.c */
    { &hf_ieee80211_ht_cap,
      { "HT Capabilities Info", "wlan.ht.capabilities",
        FT_UINT16, BASE_HEX, NULL, 0, "HT Capabilities information", HFILL
      }
    },
    { &hf_ieee80211_ht_ldpc_coding,
      { "HT LDPC coding capability", "wlan.ht.capabilities.ldpccoding",
        FT_BOOLEAN, 16, TFS(&ht_ldpc_coding_flag), 0x0001, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_chan_width,
      { "HT Support channel width", "wlan.ht.capabilities.width",
        FT_BOOLEAN, 16, TFS(&ht_chan_width_flag), 0x0002, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_sm_pwsave,
      { "HT SM Power Save", "wlan.ht.capabilities.sm",
        FT_UINT16, BASE_HEX, VALS(ht_sm_pwsave_flag), 0x000c, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_green,
      { "HT Green Field", "wlan.ht.capabilities.green",
        FT_BOOLEAN, 16, TFS(&ht_green_flag), 0x0010, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_short20,
      { "HT Short GI for 20MHz", "wlan.ht.capabilities.short20",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0020, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_short40,
      { "HT Short GI for 40MHz", "wlan.ht.capabilities.short40",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0040, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_tx_stbc,
      { "HT Tx STBC", "wlan.ht.capabilities.txstbc",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0080, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_rx_stbc,
      { "HT Rx STBC", "wlan.ht.capabilities.rxstbc",
        FT_UINT16, BASE_HEX, VALS(ht_rx_stbc_flag), 0x0300, "HT Tx STBC", HFILL
      }
    },
    { &hf_ieee80211_ht_delayed_block_ack,
      { "HT Delayed Block ACK", "wlan.ht.capabilities.delayedblockack",
        FT_BOOLEAN, 16, TFS(&ht_delayed_block_ack_flag), 0x0400, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_max_amsdu,
      { "HT Max A-MSDU length", "wlan.ht.capabilities.amsdu",
        FT_BOOLEAN, 16, TFS(&ht_max_amsdu_flag), 0x0800, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_dss_cck_40,
      { "HT DSSS/CCK mode in 40MHz", "wlan.ht.capabilities.dsscck",
        FT_BOOLEAN, 16, TFS(&ht_dss_cck_40_flag), 0x1000, "HT DSS/CCK mode in 40MHz", HFILL
      }
    },
    { &hf_ieee80211_ht_psmp,
      { "HT PSMP Support", "wlan.ht.capabilities.psmp",
        FT_BOOLEAN, 16, TFS(&ht_psmp_flag), 0x2000, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_40_mhz_intolerant,
      { "HT Forty MHz Intolerant", "wlan.ht.capabilities.40mhzintolerant",
        FT_BOOLEAN, 16, TFS(&ht_40_mhz_intolerant_flag), 0x4000, NULL, HFILL
      }
    },
    { &hf_ieee80211_ht_l_sig,
      { "HT L-SIG TXOP Protection support", "wlan.ht.capabilities.lsig",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000, NULL, HFILL
      }
    },
    { &hf_ieee80211_ampduparam,
      { "A-MPDU Parameters", "awdl.ht.ampduparam",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
      }
    },
    { &hf_ieee80211_ampduparam_mpdu,
      { "Maximum Rx A-MPDU Length", "wlan.ht.ampduparam.maxlength",
        FT_UINT8, BASE_HEX, 0, 0x03, NULL, HFILL
      }
    },
    { &hf_ieee80211_ampduparam_mpdu_start_spacing,
      { "MPDU Density", "wlan.ht.ampduparam.mpdudensity",
        FT_UINT8, BASE_HEX, VALS(ampduparam_mpdu_start_spacing_flags), 0x1c, NULL, HFILL
      }
    },
    { &hf_ieee80211_ampduparam_reserved,
      { "Reserved", "wlan.ht.ampduparam.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL
      }
    },
    { &hf_ieee80211_mcsset,
      { "Rx Supported Modulation and Coding Scheme Set", "wlan.ht.mcsset",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
      }
    },
    { &hf_ieee80211_mcsset_rx_bitmask,
      { "Rx Modulation and Coding Scheme (One bit per modulation)", "wlan.ht.mcsset.rxbitmask",
        FT_NONE, BASE_NONE, NULL, 0, "One bit per modulation", HFILL
      }
    },
    { &hf_ieee80211_mcsset_rx_bitmask_0to7,
      { "Rx Bitmask Bits 0-7", "wlan.ht.mcsset.rxbitmask.0to7",
        FT_UINT32, BASE_HEX, 0, 0x000000ff, NULL, HFILL
      }
    },
    { &hf_ieee80211_mcsset_rx_bitmask_8to15,
      { "Rx Bitmask Bits 8-15", "wlan.ht.mcsset.rxbitmask.8to15",
        FT_UINT32, BASE_HEX, 0, 0x0000ff00, NULL, HFILL
      }
    },
    { &hf_ieee80211_mcsset_rx_bitmask_16to23,
      { "Rx Bitmask Bits 16-23", "wlan.ht.mcsset.rxbitmask.16to23",
        FT_UINT32, BASE_HEX, 0, 0x00ff0000, NULL, HFILL
      }
    },
    { &hf_ieee80211_mcsset_rx_bitmask_24to31,
      { "Rx Bitmask Bits 24-31", "wlan.ht.mcsset.rxbitmask.24to31",
        FT_UINT32, BASE_HEX, 0, 0xff000000, NULL, HFILL
      }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_awdl_data,
    &ett_awdl,
    &ett_awdl_fixed_parameters,
    &ett_awdl_tagged_parameters,
    &ett_awdl_unknown,
    &ett_awdl_tag,
    &ett_awdl_channelseq_flags,
    &ett_awdl_version,
    &ett_awdl_dns_record,
    &ett_awdl_dns_name,
    &ett_awdl_channelseq_channel_list,
    &ett_awdl_channelseq_channel,
    &ett_awdl_datastate_flags,
    &ett_awdl_datastate_social_channel_map,
    &ett_awdl_datastate_extflags,
    &ett_ieee80211_ht_capabilities,
    &ett_ieee80211_ht_ampduparam,
    &ett_ieee80211_ht_mcsset_tree,
    &ett_ieee80211_ht_mcsbit_tree,
    &ett_awdl_serviceparams_bitmask,
    &ett_awdl_serviceparams_values,
    &ett_awdl_serviceparams_value,
  };

  static ei_register_info ei[] = {
    { &ei_awdl_tag_length,
      { "awdl.tag.length.bad", PI_MALFORMED, PI_ERROR,
        "Bad tag length", EXPFILL
      }
    },
    { &ei_awdl_tag_data,
      { "awdl.tag.data.undecoded", PI_UNDECODED, PI_NOTE,
        "Dissector for AWDL tag code not implemented", EXPFILL
      }
    },
  };

  expert_module_t *expert_awdl;

  proto_awdl_data = proto_register_protocol(
                      "Apple Wireless Direct Link data frame",
                      "AWDL data",
                      "awdl_data");

  proto_awdl = proto_register_protocol(
                 "Apple Wireless Direct Link action frame",
                 "AWDL",
                 "awdl");

  static hf_register_info hf_pid[] = {
    { &hf_llc_apple_pid,
      { "PID",  "llc.apple_pid",  FT_UINT16, BASE_HEX,
        VALS(apple_pid_vals), 0x0, "Protocol ID", HFILL
      }
    }
  };

  llc_add_oui(OUI_APPLE_AWDL, "llc.apple_pid", "LLC Apple OUI PID", hf_pid, proto_awdl_data);

  expert_awdl = expert_register_protocol(proto_awdl);
  expert_register_field_array(expert_awdl, ei, array_length(ei));

  tagged_field_table = register_dissector_table("awdl.tag.number", "AWDL Tags", proto_awdl, FT_UINT8, BASE_DEC);
  awdl_register_tags();

  proto_register_field_array(proto_awdl_data, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_awdl(void) {
  static dissector_handle_t awdl_action_handle, awdl_data_handle;

  awdl_action_handle = create_dissector_handle(dissect_awdl_action, proto_awdl);
  dissector_add_uint("wlan.action.vendor_specific", OUI_APPLE_AWDL, awdl_action_handle);

  awdl_data_handle = create_dissector_handle(dissect_awdl_data, proto_awdl_data);
  dissector_add_uint("llc.apple_pid", LLC_PID_AWDL, awdl_data_handle);

  ethertype_subdissector_table = find_dissector_table("ethertype");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
