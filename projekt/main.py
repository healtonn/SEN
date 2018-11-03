#!/usr/bin/env python
import os
import sys
import struct
import json
import time
import paho.mqtt.client as paho
import bluetooth._bluetooth as bluez
import bluetooth

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])
    print()


def read_inquiry_mode(sock):
    """returns the current mode, or -1 on failure"""
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # Setup socket filter to receive only events related to the
    # read_inquiry_mode command
    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL,
            bluez.OCF_READ_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    # first read the current inquiry mode.
    bluez.hci_send_cmd(sock, bluez.OGF_HOST_CTL,
            bluez.OCF_READ_INQUIRY_MODE )

    pkt = sock.recv(255)

    status,mode = struct.unpack("xxxxxxBB", pkt)
    if status != 0: mode = -1

    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return mode

def device_inquiry_with_with_rssi(sock):
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    duration = 4
    max_responses = 255
    cmd_pkt = struct.pack("BBBBB", 0x33, 0x8b, 0x9e, duration, max_responses)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_INQUIRY, cmd_pkt)

    results = []

    done = False
    while not done:
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            pkt = pkt[3:]
            nrsp = bluetooth.get_byte(pkt[0])
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                rssi = bluetooth.byte_to_signed_int(
                        bluetooth.get_byte(pkt[1+13*nrsp+i]))
                results.append( ( addr, rssi ) )
        elif event == bluez.EVT_INQUIRY_COMPLETE:
            done = True
        elif event == bluez.EVT_CMD_STATUS:
            status, ncmd, opcode = struct.unpack("BBH", pkt[3:7])
            if status != 0:
                print("uh oh...")
                printpacket(pkt[3:7])
                done = True
        elif event == bluez.EVT_INQUIRY_RESULT:
            pkt = pkt[3:]
            nrsp = bluetooth.get_byte(pkt[0])
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                results.append( ( addr, -1 ) )
                print("[%s] (no RRSI)" % addr)
        else:
            print("unrecognized packet type 0x%02x" % ptype)


    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

    return results


def estimate_range(rssi):
    default_RSSI = -46 # rssi value at 1 meter
    RSSI_DOUBLE_RANGE_VALUE = 6.0
    CORRECTION = 1.2
    tmp = default_RSSI - rssi
    if tmp < 6:
        return 1.0

    tmp1 = tmp / RSSI_DOUBLE_RANGE_VALUE
    range = 2**tmp1
    range = range / CORRECTION

    return range


def prepare_json_data(my_data):
    my_data = json.dumps(my_data)
    my_data = my_data.encode('utf-8')
    return my_data

#define callback
def on_message(client, userdata, message):
    time.sleep(1)
    print ("received message: ", str(message.payload.decode('utf-8')))


class MQTT:
    def __init__(self):
        self.broker = "test.mosquitto.org"
        self.port = 1883

        self.client = paho.Client("python_client", self.port)
        self.client.on_message=on_message
        #print "connecting to: ", self.broker
        self.client.connect(self.broker)
        self.client.loop_start()

    def stop(self):
        self.client.disconnect()
        self.client.loop_stop()

    def publish(self, data):
        #print "publishing..."
        self.client.publish("xjochl00/SEN", data)



dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("error accessing bluetooth device...")
    sys.exit(1)

try:
    mode = read_inquiry_mode(sock)
except Exception as e:
    print("error reading inquiry mode.  ")
    print("Are you sure this a bluetooth 1.2 device?")
    print(e)
    sys.exit(1)

nearby = bluetooth.discover_devices(lookup_names=True)
list_of_devices = {}
for addr, name in nearby:
    list_of_devices[addr] = name
    if '-d' in sys.argv:
        print addr, name


if '-m' in sys.argv:
    print "not using mqtt"
else:
    mqtt = MQTT()
time_now = time.time()

while True:
    if time.time() - time_now > 15:
        nearby = bluetooth.discover_devices(lookup_names=True)
        for addr, name in nearby:
            list_of_devices[addr] = name

    data = device_inquiry_with_with_rssi(sock)
    for device in data:
        try:
            device_data = {}
            name = list_of_devices[device[0]] if device[0] in list_of_devices else "unknown"
            distance = estimate_range(device[1])
            device_data = {'MAC': device[0], 'range (meters)': distance, 'RSSI': device[1], 'Name': name}
            json_data = prepare_json_data(device_data)
            if '-d' in sys.argv:
                print json_data

            if '-m' in sys.argv:
                pass
            else:
                mqtt.publish(json_data)

        except Exception as e:
            print ("chybicka", e)

    print ''
