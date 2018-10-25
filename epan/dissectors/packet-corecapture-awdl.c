/* packet-corecapture.c
 * Routines for Apple's CoreCapture Dumps.
 * Disector for the AWDL traces. This includes text, data or action frames.
 * Many of the fields are not fully understood, but the structure can be fully
 * dissected. Therefore we are able to dissect the appended payload.
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


#define PNAME  "CoreCapture AWDL Trace"
#define PSNAME "CC AWDL"
#define PFNAME "cc.awdl"

#define CC_AWDL_TAG_LENGTH 2
#define CC_AWDL_LEN_LENGTH 2
#define CC_AWDL_HDR_LENGTH 4

#define CC_AWDLPEERMANAGER_TYPE 5

void proto_register_corecapture_awdl(void);
//void proto_reg_handoff_packetlogger(void);

static int proto_cc_awdl = -1;

static int hf_header_unknown = -1;
static int hf_count1 = -1;
static int hf_logcount = -1;
static int hf_payloadtype = -1;
static int hf_tlv_count = -1;
static int hf_timestamp = -1;
static int hf_tlv_tag = -1;
static int hf_tlv_tag_number = -1;
static int hf_tlv_len = -1;
static int hf_awdl_action_unknown1 = -1;
static int hf_unknown64 = -1;
static int hf_unknown16 = -1;
static int hf_kernel_addr = -1;
static int hf_text = -1;
static int hf_awdl_af_header = -1;
static int hf_srcaddr = -1;
static int hf_dstaddr = -1;
static int hf_ieee80211_ff_category_code = -1;
static int hf_ieee80211_tag_oui = -1;

static int hf_awdl_tag_data = -1;
static int hf_cc_awdl_tag_padding = -1;

static int hf_info1 = -1;
static int hf_info2 = -1;




static gint ett_cc_awdl_tag = -1;
static gint ett_tlv = -1;


static expert_field ei_cc_awdl_tag_length = EI_INIT;
static expert_field ei_cc_awdl_tag_data = EI_INIT;


static dissector_handle_t cc_awdl_handle;
static dissector_table_t awdl_tagged_field_table;

//AWDL events
enum {
  CC_AWDL_ACTION = 8,
  CC_AWDL_LLC = 2,
  CC_AWDL_TM = 3,
  CC_AWDL_TX = 5
};

static const value_string cc_awdl_tlv_type[] = {
  { CC_AWDL_ACTION, "AWDL Action" },
  { CC_AWDL_LLC, "AWDL LLC / Data" },
  { CC_AWDL_TM, "AWDL TM" },
  { CC_AWDL_TX, "AWDL Tx" },
  { 0, NULL }
};
static value_string_ext cc_awdl_tlv_type_ext = VALUE_STRING_EXT_INIT(cc_awdl_tlv_type);


//AWDL Payload Data Types
enum {
  CC_AWDL_PL_DATA = 0,
  CC_AWDL_PL_STRING = 2
};

static const value_string awdl_payload_types[] = {
  { CC_AWDL_PL_DATA,    "Data"},
  { CC_AWDL_PL_STRING,  "String"},
  { 0,       NULL }
};


static gint ett_corecapture_awdl = -1;

static int
corecapture_awdl_tag_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  address      src_ether_addr;
  
  proto_tree_add_item (tree, hf_srcaddr, tvb, offset, 6, ENC_NA);
  // set source column
  set_address_tvb(&src_ether_addr, AT_ETHER, 6, tvb, offset);
  col_add_fstr(pinfo->cinfo, COL_RES_DL_SRC, "%s",address_with_resolution_to_str(wmem_packet_scope(), &src_ether_addr)
               );
  offset+=6;
  
  proto_tree_add_item (tree, hf_header_unknown, tvb, offset, 6, ENC_NA);
  offset+=6;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN); //channel
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);//channel flags?
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_header_unknown, tvb, offset, 2, ENC_NA);
  offset+=4;
  proto_tree_add_item (tree, hf_header_unknown, tvb, offset, 2, ENC_NA);
  offset+=2;
  proto_tree_add_item (tree, hf_header_unknown, tvb, offset, 4, ENC_NA);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN); //counter
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  //proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  //offset+=4;
  
  return offset;
}

static int
corecapture_awdl_add_tagged_field(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  tvbuff_t     *tag_tvb;
  guint32       tag_no, tag_len;
  proto_tree   *orig_tree = tree;
  proto_item   *ti        = NULL;
  proto_item   *ti_len, *ti_tag;
  awdl_tagged_field_data_t field_data;
  int parsed;
  
  tag_no = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
  tag_len = tvb_get_guint16(tvb, offset + CC_AWDL_TAG_LENGTH, ENC_LITTLE_ENDIAN);
  
  if (tree) {
    ti = proto_tree_add_item(orig_tree, hf_tlv_tag, tvb, offset, tag_len + CC_AWDL_HDR_LENGTH, ENC_NA);
    proto_item_append_text(ti, ": %s", val_to_str_ext(tag_no, &cc_awdl_tlv_type_ext, "Unknown (%d)"));
    tree = proto_item_add_subtree(ti, ett_cc_awdl_tag);
  }
  
  ti_tag = proto_tree_add_uint(tree, hf_tlv_tag_number, tvb, offset, CC_AWDL_TAG_LENGTH, tag_no);
  ti_len = proto_tree_add_uint(tree, hf_tlv_len, tvb, offset + CC_AWDL_TAG_LENGTH, CC_AWDL_LEN_LENGTH, tag_len);
  
  offset += CC_AWDL_HDR_LENGTH;
  
  /* if (tag_len > (guint)tvb_reported_length_remaining(tvb, offset)) {
   expert_add_info_format(pinfo, ti_len, &ei_awdl_tag_length,
   "Tag Length is longer than remaining payload");
   }*/
  
  tag_tvb = tvb_new_subset_length(tvb, offset, tag_len);
  field_data.item_tag = ti;
  field_data.item_tag_length = ti_len;
  if (!(parsed = dissector_try_uint_new(awdl_tagged_field_table, tag_no, tag_tvb, pinfo, tree, FALSE, &field_data)))
  {
    proto_tree_add_item(tree, hf_awdl_tag_data, tag_tvb, 0, tag_len, ENC_NA);
    expert_add_info_format(pinfo, ti_tag, &ei_cc_awdl_tag_data,
                           "Dissector for CC AWDL tag (%s) code not implemented",
                           val_to_str_ext(tag_no, &cc_awdl_tlv_type_ext, "(%d)"));
    proto_item_append_text(ti, ": Undecoded");
  }
  else if (parsed > 0 && (unsigned int) parsed < tag_len)
  {
    proto_tree_add_item(tree, hf_cc_awdl_tag_padding, tag_tvb, parsed, tag_len - parsed, ENC_NA);
  }
  
  return tag_len + CC_AWDL_HDR_LENGTH;
}

/*
 * Not sure what this field holds.
 */
static int
corecapture_awdl_tag_tm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN); //frame id
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  
  return offset;
}
static int
corecapture_awdl_tag_tx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  proto_tree_add_item (tree, hf_unknown16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset+=2;
  return offset;
}


static int
corecapture_awdl_tag_llc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
  int offset = 0;
  int remaining_len;
  
  proto_tree_add_item (tree, hf_header_unknown, tvb, offset, 70, ENC_NA);
  offset+=70;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (tree, hf_awdl_action_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  // This field seems to be used in different lengths.
  remaining_len = tvb_reported_length_remaining(tvb, offset);
  proto_tree_add_item(tree, hf_header_unknown, tvb, offset, remaining_len, ENC_NA);
  offset+=remaining_len;
  
  return offset;
}

static int dissect_corecapture_awdl(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, void *data _U_)
{
  proto_tree                *corecapture_tree = NULL;
  tvbuff_t                    *next_tvb;
  proto_item                *ti = NULL;
  guint16                          tlv_tag;
  guint8                    tlv_count, pl_type, data_type;
  gint                             len;
  int                         offset=0;
  char *infotext, *longtext;
  gboolean is_awdl_action_frame = FALSE;
  
  dissector_handle_t next_handle;
  
  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);
  
  ti = proto_tree_add_item (tree, proto_cc_awdl, tvb, 0, -1, ENC_NA);
  corecapture_tree = proto_item_add_subtree (ti, ett_corecapture_awdl);
  
  proto_tree_add_item (corecapture_tree, hf_info1, tvb, offset, 64, ENC_ASCII | ENC_NA);
  offset+=64;
  
  
  proto_tree_add_item (corecapture_tree, hf_info2, tvb, offset, 64, ENC_ASCII | ENC_NA);
  infotext = tvb_get_stringzpad(wmem_packet_scope(), tvb, offset, 64, ENC_ASCII | ENC_NA);
  col_add_fstr (pinfo->cinfo, COL_INFO, "CC: %s ", infotext);
  offset+=64;
  
  proto_tree_add_item (corecapture_tree, hf_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset+=8;
  
  proto_tree_add_item (corecapture_tree, hf_logcount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset+=4;
  proto_tree_add_item (corecapture_tree, hf_payloadtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  pl_type = tvb_get_guint8(tvb, offset);
  
  offset+=1;
  proto_tree_add_item (corecapture_tree, hf_tlv_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  tlv_count = tvb_get_guint8(tvb, offset);
  offset+=1;
  //TODO: Fill
  offset+=2;
  proto_tree_add_item (corecapture_tree, hf_kernel_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset+=8;
  
  
  //data
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 2, ENC_NA);
  offset+=2;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 2, ENC_NA);
  offset+=2;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 4, ENC_NA);
  offset+=4;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 8, ENC_NA);
  offset+=8;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 8, ENC_NA);
  offset+=8;
  proto_tree_add_item (corecapture_tree, hf_header_unknown, tvb, offset, 8, ENC_NA);
  offset+=8;
  
  
  
  
  data_type=0;
  
  if (tlv_count>0) {
    tlv_tag = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    //if the first TLV is ACTION, the payload contains an AF, otherwise it is Ethernet data.
    is_awdl_action_frame = (tlv_tag == CC_AWDL_ACTION);
  }
  
  for (int i=0; i<tlv_count; i++) {
    offset+=corecapture_awdl_add_tagged_field(pinfo, corecapture_tree, tvb, offset);
  }
  
  if (pl_type== CC_AWDL_PL_STRING) {
    longtext = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, NULL, ENC_ASCII | ENC_NA);
    // remove newline after text
    size_t last_char = strlen(longtext)-1;
    if (longtext[last_char]=='\n') {
      longtext[last_char]='\0';
    }
    
    proto_tree_add_item (corecapture_tree, hf_text, tvb, offset, -1, ENC_ASCII | ENC_NA);
    col_add_fstr (pinfo->cinfo, COL_INFO, "%s", longtext);
    col_add_fstr (pinfo->cinfo, COL_RES_DL_SRC, "%s", infotext);
    
  } else  {
    //Forces following dissectors to append
    col_set_fence(pinfo->cinfo, COL_INFO);
    
    if (is_awdl_action_frame) {
      guint32 oui;
      tvbuff_t *vendor_tvb;
      dissector_table_t vendor_specific_action_table;
      vendor_specific_action_table = find_dissector_table("wlan.action.vendor_specific");
      //TODO: We could try to modify the 802.11 dissector to be able to parse these two fields correctly.
      proto_tree_add_item(corecapture_tree, hf_ieee80211_ff_category_code, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item_ret_uint(corecapture_tree, hf_ieee80211_tag_oui, tvb, offset, 3, ENC_BIG_ENDIAN, &oui);
      offset += 3;
      len = tvb_reported_length_remaining (tvb, offset);
      
      vendor_tvb = tvb_new_subset_length(tvb, offset, len);
      dissector_try_uint_new(vendor_specific_action_table, oui, vendor_tvb, pinfo, tree, FALSE, NULL);
    } else {
      // dissect as Ethernet frame
      proto_item_set_len (ti, offset);
      next_handle = find_dissector("eth_withoutfcs");
      len = tvb_reported_length_remaining (tvb, offset);
      next_tvb = tvb_new_subset_length(tvb, offset, len);
      call_dissector(next_handle, next_tvb, pinfo, tree);
      
    }
  }
  return tvb_captured_length(tvb);
}



static void
corecapture_awdl_register_tags()
{
  dissector_add_uint("corecapture.awdl.tlv.tag", CC_AWDL_ACTION, create_dissector_handle(corecapture_awdl_tag_action, -1));
  dissector_add_uint("corecapture.awdl.tlv.tag", CC_AWDL_LLC, create_dissector_handle(corecapture_awdl_tag_llc, -1));
  dissector_add_uint("corecapture.awdl.tlv.tag", CC_AWDL_TM, create_dissector_handle(corecapture_awdl_tag_tm, -1));
  dissector_add_uint("corecapture.awdl.tlv.tag", CC_AWDL_TX, create_dissector_handle(corecapture_awdl_tag_tx, -1));
}

void proto_register_corecapture_awdl (void)
{
  static hf_register_info hf[] = {
    { &hf_header_unknown,
      { "Unknown", "corecapture.awdl.header.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_count1,
      { "Counter 1", "corecapture.awdl.count1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_logcount,
      { "Logcount", "corecapture.awdl.logcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_payloadtype,
      { "Payload Type", "corecapture.awdl.payloadtype", FT_UINT8, BASE_DEC, VALS(awdl_payload_types), 0x0, NULL, HFILL } },
    { &hf_tlv_count,
      { "Number of TLV Fields", "corecapture.awdl.tlv_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_timestamp,
      { "Timestamp", "corecapture.awdl.timestamp", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_tlv_tag,
      { "Tag", "awdl.tag",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_tlv_tag_number,
      { "Payload Type", "corecapture.awdl.type", FT_UINT16, BASE_DEC, VALS(cc_awdl_tlv_type), 0x0, NULL, HFILL } },
    { &hf_tlv_len,
      { "Payload Header Length", "corecapture.awdl.tlv.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_awdl_action_unknown1,
      { "Unknown 1", "corecapture.awdl.unknown1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_unknown64,
      { "Unknown 64 bit", "corecapture.awdl.unknown2", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_unknown16,
      { "Unknown 16 bit", "corecapture.awdl.unknown3", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    
    { &hf_kernel_addr,
      { "Addr", "corecapture.awdl.addr", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_text,
      { "Text", "corecapture.awdl.text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_awdl_af_header,
      { "AF Header", "corecapture.awdl.af_header", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_srcaddr,
      { "Source", "corecapture.awdl.src", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dstaddr,
      { "Destination", "corecapture.awdl.dst",FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    {&hf_ieee80211_ff_category_code,
      {"Category code", "wlan.fixed.category_code",
        FT_UINT16, BASE_DEC, NULL, 0,
        "Management action category", HFILL }},
    {&hf_ieee80211_tag_oui,
      {"OUI", "wlan.tag.oui",
        FT_UINT24, BASE_OUI, NULL, 0,
        "OUI of vendor specific IE", HFILL }},
    { &hf_awdl_tag_data,
      { "Tag Data", "corecapture.awdl.tag.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Data Interpretation of tag", HFILL
      }
    },
    { &hf_cc_awdl_tag_padding,
      { "Padding (?)", "corecapture.awdl.tlv.padding",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Unused (?) bytes at the end of the tag", HFILL
      }
    },
    { &hf_info1,
      { "Info 1", "corecapture.awdl.info1", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_info2,
      { "Info 2", "corecapture.awdl.info2", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
  };
  
  static gint *ett[] = {
    &ett_corecapture_awdl,
    &ett_tlv,
    &ett_cc_awdl_tag
  };
  expert_module_t *expert_cc_awdl;
  
  static ei_register_info ei[] = {
    { &ei_cc_awdl_tag_length,
      { "cc.awdl.tag.length.bad", PI_MALFORMED, PI_ERROR,
        "Bad tag length", EXPFILL
      }
    },
    { &ei_cc_awdl_tag_data,
      { "cc.awdl.tag.data.undecoded", PI_UNDECODED, PI_NOTE,
        "Dissector for AWDL tag code not implemented", EXPFILL
      }
    },
  };
  
  proto_cc_awdl = proto_register_protocol (PNAME, PSNAME, PFNAME);
  
  cc_awdl_handle = register_dissector (PFNAME, dissect_corecapture_awdl, proto_cc_awdl);
  
  expert_cc_awdl = expert_register_protocol(proto_cc_awdl);
  expert_register_field_array(expert_cc_awdl, ei, array_length(ei));
  
  proto_register_field_array (proto_cc_awdl, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  
  dissector_add_uint("corecapture.streamheader", CC_AWDLPEERMANAGER_TYPE, cc_awdl_handle);

  
  awdl_tagged_field_table = register_dissector_table("corecapture.awdl.tlv.tag", "CC AWDL Tags", proto_cc_awdl, FT_UINT8, BASE_DEC);
  corecapture_awdl_register_tags();
  
}

