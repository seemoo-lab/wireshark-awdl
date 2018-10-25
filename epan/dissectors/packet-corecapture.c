/* packet-corecapture.c
 * Routines for Apple's CoreCapture Dumps
 * This dissector just analyzes the first bytes to determine the right sub dissector. 
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


void proto_register_corecapture(void);

#define PNAME  "CoreCapture"
#define PSNAME "CC"
#define PFNAME "corecapture"

#define CC_STREAM_HDR_LENGTH 8



static int proto_corecapture = -1;

static int hf_cc_frame_type = -1;
static int hf_cc_frame_additional = -1;


// CoreCapture Frame / Trace Types
enum {
  CC_CONTROLPATH_EVENT2 = 2,
  CC_IOCTL = 3,
  CC_ETH_TYPE = 4,
  CC_AWDLPEERMANAGER_TYPE = 5,
  CC_CONTROLPATH_IOCTL = 6,
  CC_CONTROLPATH_EVENT = 7,
  CC_UNKNOWN1 = 0xa, // appears in iOS Datapath
  CC_UNKNOWN2 = 0xb, // appears in iOS Datapath
  CC_FW_BUS_TYPE = 0xd,
  CC_LAST_TYPE = 0xaeae
};

static const value_string cc_frame_type[] = {
  { CC_CONTROLPATH_EVENT, "Control Path Event" },
  { CC_CONTROLPATH_EVENT2, "Control Path Event" },
  { CC_CONTROLPATH_IOCTL, "Control Path IOCTL" },
  { CC_IOCTL, "IOCTL" },
  { CC_AWDLPEERMANAGER_TYPE, "AWDLPeerManager" },
  { CC_ETH_TYPE, "Ethernet Frame" },
  { CC_LAST_TYPE, "Empty" },
  { 0, NULL }
};
static value_string_ext cc_frame_type_ext = VALUE_STRING_EXT_INIT(cc_frame_type);



static gint ett_corecapture = -1;


static dissector_handle_t corecapture_handle;
static dissector_table_t streamheader_field_table;


/*
 CoreCapture traces start with a 8 byte header. The dissection of the appended data, such as AWDL and Ethernet
 is implemented in a separate file.
 
*/
static int dissect_corecapture(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, void *data _U_)
{
  proto_tree                *corecapture_tree = NULL;
  proto_item                *ti = NULL;
  tvbuff_t     *payload_tvb;
  int offset = 0;
  int parsed;
  
  ti = proto_tree_add_item (tree, proto_corecapture, tvb, 0, -1, ENC_NA);
  corecapture_tree = proto_item_add_subtree (ti, ett_corecapture);
  
  ti = proto_tree_add_item (corecapture_tree, hf_cc_frame_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  guint32 frame_type = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN);
  
  proto_item_append_text(ti, ": %s", val_to_str_ext(frame_type, &cc_frame_type_ext, "Unknown (%d)"));
  offset+=4;
  proto_tree_add_item (corecapture_tree, hf_cc_frame_additional, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  
  int remaining_length = tvb_reported_length_remaining (tvb, offset) + CC_STREAM_HDR_LENGTH;
  payload_tvb = tvb_new_subset_length(tvb, offset, remaining_length);
  tvb_new_subset_remaining(tvb, offset);
  parsed = dissector_try_uint_new(streamheader_field_table, frame_type, payload_tvb, pinfo, tree, FALSE, NULL);
  
  if (!parsed) {
    //TODO: expert info
  }
  return parsed;
  
}







void proto_register_corecapture (void)
{
  static hf_register_info hf[] = {
    { &hf_cc_frame_type,
      { "Streamheader", "corecapture.streamheader", FT_UINT32, BASE_DEC, VALS(cc_frame_type), 0x0, NULL, HFILL } },
    { &hf_cc_frame_additional,
      { "Streamheader Additional", "corecapture.streamheader.additioanal", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
  };
  
  static gint *ett[] = {
    &ett_corecapture,
  };
  
  proto_corecapture = proto_register_protocol (PNAME, PSNAME, PFNAME);
  
  corecapture_handle = register_dissector (PFNAME, dissect_corecapture, proto_corecapture);
  
  proto_register_field_array (proto_corecapture, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  
  streamheader_field_table = register_dissector_table("corecapture.streamheader", "Stream Header", proto_corecapture, FT_UINT32, BASE_DEC);
  
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

