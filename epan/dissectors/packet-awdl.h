/* packet-awdl.h
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

#ifndef __PACKET_AWDL_H__
#define __PACKET_AWDL_H__

typedef struct awdl_tagged_field_data
{
  proto_item* item_tag;
  proto_item* item_tag_length;
} awdl_tagged_field_data_t;

int dissect_awdl_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
int dissect_awdl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

#endif /* __PACKET_AWDL_H__ */

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
