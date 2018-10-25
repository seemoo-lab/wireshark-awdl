/* packet-corecapture.c
 * Routines for Apple's CoreCapture Dumps
 * Disect the interface name and some unknown data and forward to regular eth dissector.
 *
 * Copyright 2017-2018, David Kreitschmann <david@kreitschmann.de>
 *
 * Released as part of:
 *   Milan Stute, David Kreitschmann, and Matthias Hollick. "One Billion Apples'
 *   Secret Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol"
 *   in ACM MobiCom '18. https://doi.org/10.1145/3241539.3241566
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>
#include <epan/wmem/wmem.h>

#include <epan/address_types.h>
#include <epan/addr_resolv.h>

#include <epan/dissectors/packet-awdl.h>

#include <epan/dissectors/packet-ieee80211.h>


void proto_register_corecapture_ethernet(void);
//void proto_reg_handoff_packetlogger(void);

#define PNAME  "CoreCapture Ethernet Trace"
#define PSNAME "CC ETH"
#define PFNAME "corecapture.ethernet"

#define CC_STREAM_HDR_LENGTH 8
#define CC_ETH_TYPE 4



static int proto_corecapture_ethernet = -1;
static int hf_header_unknown = -1;
static int hf_interfacename = -1;

static gint ett_cc_eth = -1;

static dissector_handle_t cc_eth_handle;

static int dissect_corecapture_ethernet(tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, void *data _U_)
{
  proto_tree                *corecapture_tree = NULL;
  tvbuff_t                    *next_tvb;
  proto_item                *ti = NULL;
  gint                             len;
  int                         offset=0;
  
  dissector_handle_t next_handle;
  
  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);
  
  ti = proto_tree_add_item (tree, proto_corecapture_ethernet, tvb, 0, -1, ENC_NA);
  corecapture_tree = proto_item_add_subtree (ti, ett_cc_eth);
  
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 10, ENC_NA);
  offset+=10;
  proto_tree_add_item (corecapture_tree, hf_interfacename, tvb, offset, 4, ENC_NA);
  offset+=4;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 2, ENC_NA);
  offset+=2;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 40, ENC_NA);
  offset+=40;
  
  proto_item_set_len (ti, offset);
  next_handle = find_dissector("eth_withoutfcs");
  len = tvb_reported_length_remaining (tvb, offset);
  next_tvb = tvb_new_subset_length(tvb, offset, len);
  call_dissector(next_handle, next_tvb, pinfo, tree);
  
  
  return tvb_captured_length(tvb);
  
}

void proto_register_corecapture_ethernet (void)
{
  static hf_register_info hf[] = {
    { &hf_interfacename,
      { "Interface", "corecapture.eth.interface", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_header_unknown,
      { "Unknown", "corecapture.eth.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
  };
  
  static gint *ett[] = {
    &ett_cc_eth,
  };
  
  proto_corecapture_ethernet = proto_register_protocol (PNAME, PSNAME, PFNAME);
  
  cc_eth_handle = register_dissector (PFNAME, dissect_corecapture_ethernet, proto_corecapture_ethernet);
  
  proto_register_subtree_array (ett, array_length (ett));
  proto_register_field_array (proto_corecapture_ethernet, hf, array_length (hf));

  
  dissector_add_uint("corecapture.streamheader", CC_ETH_TYPE, cc_eth_handle);

}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

