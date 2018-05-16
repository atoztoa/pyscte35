#!/usr/bin/python
'''

SCTE-35 Decoder


The MIT License (MIT)

Copyright (c) 2014 Al McCormack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

'''


from datetime import timedelta
from enum import IntEnum
import bitstring
import base64
import json
import sys
import binascii

SEGMENTATION_TYPE_IDS = {
  "00": "Not Indicated",
  "01": "Content Identification",
  "10": "Program Start",
  "11": "Program End",
  "12": "Program Early Termination",
  "13": "Program Breakaway",
  "14": "Program Resumption",
  "15": "Program Runover Planned",
  "16": "Program Runover Unplanned",
  "17": "Program Overlap Start",
  "18": "Program Blackout Override",
  "19": "Program Start – In Progress",
  "20": "Chapter Start",
  "21": "Chapter End",
  "22": "Break Start",
  "23": "Break End",
  "30": "Provider Advertisement Start",
  "31": "Provider Advertisement End",
  "32": "Distributor Advertisement Start",
  "33": "Distributor Advertisement End",
  "34": "Provider Placement Opportunity Start",
  "35": "Provider Placement Opportunity End",
  "36": "Distributor Placement Opportunity Start",
  "37": "Distributor Placement Opportunity End",
  "40": "Unscheduled Event Start",
  "41": "Unscheduled Event End",
  "50": "Network Start",
  "51": "Network End"
}

class SpliceDescriptor(IntEnum):
  AVAIL_DESCRIPTOR = 0
  DTMF_DESCRIPTOR = 1
  SEGMENTATION_DESCRIPTOR = 2
  TIME_DESCRIPTOR = 3


class MPEG_Time(int):
  """ Relative time represented by 90kHz clock """

  @property
  def seconds(self):
    return self / 90000.0

  @property
  def timedelta(self):
    return timedelta(seconds=self.seconds)

  def __repr__(self, *args, **kwargs):
    return "%d (seconds: %f, time: %s)" % (self, self.seconds, self.timedelta)


class SCTE35_Parser(object):
  def parse(self, input_bytes):
    input_bitarray = bitstring.BitString(bytes=input_bytes)

    table_id = input_bitarray.read("uint:8")

    if table_id != 0xfc:
      raise Exception("table_id %d invalid. Should be 0xfc" % table_id)

    splice_info_section = {}

    splice_info_section["section_syntax_indicator"] = input_bitarray.read("bool")
    splice_info_section["private_indicator"] = input_bitarray.read("bool")

    input_bitarray.pos += 2
    splice_info_section["section_length"] = input_bitarray.read("uint:12")
    splice_info_section["protocol_version"] = input_bitarray.read("uint:8")
    splice_info_section["encrypted_packet"] = input_bitarray.read("bool")
    splice_info_section["encryption_algorithm"] = input_bitarray.read("uint:6")
    splice_info_section["pts_adjustment"] = input_bitarray.read("uint:33")
    splice_info_section["cw_index"] = input_bitarray.read("uint:8")
    splice_info_section["tier"] = input_bitarray.read("hex:12")
    splice_info_section["splice_command_length"] = input_bitarray.read("uint:12")

    splice_info_section["splice_command_type"] = input_bitarray.read("uint:8")

    # splice command type parsing
    if splice_info_section["splice_command_type"] == 5:
      splice_info_section["splice_command"] = self.__parse_splice_insert(input_bitarray)
    elif splice_info_section["splice_command_type"] == 6:
      splice_info_section["splice_command"] = self.__parse_time_signal(input_bitarray)
    else:
      raise Exception("splice_command_type: %d not yet supported" % splice_info_section["splice_command_type"])

    # Total bytes in splice_descriptors
    splice_info_section["splice_descriptor_loop_length"] = input_bitarray.read("uint:16")
    splice_info_section["splice_descriptors"] = None

    if splice_info_section["splice_descriptor_loop_length"] > 0:
      try:
        splice_info_section["splice_descriptors"] = (
         self.__parse_splice_descriptors(input_bitarray,
                         splice_info_section["splice_descriptor_loop_length"]))
      except Exception as err:
        print(err)

    return splice_info_section

  def __parse_splice_time(self, bitarray):
    splice_time = {}
    splice_time["time_specified_flag"] = bitarray.read("bool")

    if splice_time["time_specified_flag"]:
      # Reserved for 6 bits
      bitarray.pos += 6
      splice_time["pts_time"] = MPEG_Time(bitarray.read("uint:33"))
    else:
      bitarray.pos += 7

    return splice_time

  def __parse_break_duration(self, bitarray):
    break_duration = {}
    break_duration["auto_return"] = bitarray.read("bool")
    bitarray.pos += 6
    break_duration["duration"] = MPEG_Time(bitarray.read("uint:33"))
    return break_duration

  def __parse_splice_insert(self, bitarray):
    splice_event_id = bitarray.read("uint:32")
    ssi = {}

    ssi["splice_id"] = splice_event_id
    ssi["components"] = []

    ssi["splice_event_cancel_indicator"] = bitarray.read("bool")
    bitarray.pos += 7

    if not ssi["splice_event_cancel_indicator"]:
      ssi["out_of_network_indicator"] = bitarray.read("bool")
      ssi["program_splice_flag"] = bitarray.read("bool")
      ssi["duration_flag"] = bitarray.read("bool")
      ssi["splice_immediate_flag"] = bitarray.read("bool")
      # Next 4 bits are reserved
      bitarray.pos += 4

      if ssi["program_splice_flag"] and not ssi["splice_immediate_flag"]:
        ssi["splice_time"] = self.__parse_splice_time(bitarray)

      if not ssi["program_splice_flag"]:
        ssi["component_count"] = bitarray.read("uint:8")

        for i in xrange(0, ssi["component_count"]):
          component = {}

          component["tag"] = bitarray.read("uint:8")
          component["splice_time"] = None


          if ssi["splice_immediate_flag"]:
            component["splice_time"] = self.__parse_splice_time(bitarray)
          ssi["components"].append(component)


      if ssi["duration_flag"]:
        ssi["break_duration"] = self.__parse_break_duration(bitarray)

      ssi["unique_program_id"] = bitarray.read("uint:16")
      ssi["avail_num"] = bitarray.read("uint:8")
      ssi["avails_expected"] = bitarray.read("uint:8")
      return ssi

  def __parse_time_signal(self, bitarray):
    ssi = {}

    ssi["splice_time"] = self.__parse_splice_time(bitarray)
    return ssi

  def __parse_segmentation_descriptor(self, bitarray, tag, length):
    segmentation_descriptor = {}

    segmentation_descriptor["splice_descriptor_tag"] = tag
    segmentation_descriptor["descriptor_length"] = length

    segmentation_descriptor["identifier"] = bitarray.read("uint:32")

    descriptor_data_length = segmentation_descriptor["descriptor_length"] - 4

    segmentation_descriptor["segmentation_event_id"] = bitarray.read("uint:32")
    segmentation_descriptor["segmentation_event_cancel_indicator"] = bitarray.read("bool")

    # Reserved bits
    bitarray.pos += 7

    if not segmentation_descriptor["segmentation_event_cancel_indicator"]:
      segmentation_descriptor["program_segmentation_flag"] = bitarray.read("bool")
      segmentation_descriptor["segmentation_duration_flag"] = bitarray.read("bool")
      segmentation_descriptor["delivery_not_restricted_flag"] = bitarray.read("bool")

      if not segmentation_descriptor["delivery_not_restricted_flag"]:
        segmentation_descriptor["web_delivery_allowed_flag"] = bitarray.read("bool")
        segmentation_descriptor["no_regional_blackout_flag"] = bitarray.read("bool")
        segmentation_descriptor["archive_allowed_flag"] = bitarray.read("bool")
        segmentation_descriptor["device_restrictions"] = bitarray.read("uint:2")
      else:
        bitarray.pos += 5

      if not segmentation_descriptor["program_segmentation_flag"]:
        segmentation_descriptor["component_count"] = bitarray.read("uint:8")
        segmentation_descriptor["components"] = []

        for i in range(segmentation_descriptor["component_count"]):
          component = {}
          component["component_tag"] = bitarray.read("uint:8")
          bitarray.pos += 7
          component["pts_offset"] = bitarray.read("uint:33")

          segmentation_descriptor["components"].append(component)

      if segmentation_descriptor["segmentation_duration_flag"]:
        segmentation_descriptor["segmentation_duration"] = bitarray.read("uint:40")

      segmentation_descriptor["segmentation_upid_type"] = bitarray.read(8).hex
      segmentation_descriptor["segmentation_upid_length"] = bitarray.read("uint:8")



      segmentation_descriptor["segmentation_upid"] = self.__parse_segmentation_upid(
        bitarray,
        int(segmentation_descriptor["segmentation_upid_type"], 16),
        segmentation_descriptor["segmentation_upid_length"]
      )

      segmentation_descriptor["segmentation_type_id"] = bitarray.read(8).hex
      segmentation_descriptor["segment_num"] = bitarray.read("uint:8")
      segmentation_descriptor["segments_expected"] = bitarray.read("uint:8")

      if segmentation_descriptor["segmentation_type_id"] in ["34", "36"]:
        segmentation_descriptor["sub_segment_num"] = bitarray.read("uint:8")
        segmentation_descriptor["sub_segments_expected"] = bitarray.read("uint:8")

      if segmentation_descriptor["segmentation_type_id"] in SEGMENTATION_TYPE_IDS:
        segmentation_descriptor["segmentation_type_id"] = SEGMENTATION_TYPE_IDS[segmentation_descriptor["segmentation_type_id"]]

    return segmentation_descriptor

  def __parse_segmentation_upid(self, bitarray, upid_type, length):
    return bitarray.read(length * 8).hex


  def __parse_splice_descriptors(self, bitarray, length):
    results = []

    while length:
      splice_descriptor_tag = bitarray.read("uint:8")

      if bitarray.pos == bitarray.len:
        splice_descriptor = {
          "splice_descriptor_tag": splice_descriptor_tag,
          "descriptor_length": 0
        }

        length = 0
      else:
        descriptor_length = bitarray.read("uint:8")

        length -= descriptor_length + 2

        if splice_descriptor_tag == SpliceDescriptor.SEGMENTATION_DESCRIPTOR:
          splice_descriptor = self.__parse_segmentation_descriptor(bitarray, splice_descriptor_tag, descriptor_length)
        else:
          splice_descriptor = {
            "splice_descriptor_tag": splice_descriptor_tag,
            "descriptor_length": descriptor_length
          }

      results.append(splice_descriptor)
    return results

if __name__ == "__main__":
  scte_strings = sys.argv[1:]

  for scte_string in scte_strings:
    try:
      input_bytes = base64.standard_b64decode(scte_string)
      splice_info_section = SCTE35_Parser().parse(input_bytes)

      print("Parsing Complete")
      print(json.dumps(splice_info_section, indent=2))
    except Exception as err:
      print(err)
