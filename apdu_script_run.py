

import sys
import os
import stat
import requests
from time import sleep
from threading import Thread, Event
from smartcard.System import readers
from smartcard.CardRequest import CardRequest
from smartcard.util import *


command_index = 0
card_connected = False
adm_verify = False


def error(e, command_index=None):
    out = "   Error"
    if command_index is not None:
        out += " on line %d" % command_index
    out += ": " + str(e)
    return out


class AdmError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Connection(object):

    __connection = None

    class Monitoring(Thread):

        def __init__(self, observer, reader):
            Thread.__init__(self)
            self.reader = reader
            self.observer = observer
            self.stopEvent = Event()
            self.stopEvent.clear()
            self.initializedEvent = Event()
            self.initializedEvent.clear()
            self.setDaemon(True)
            self.card = None

        def run(self):
            self.cardrequest = CardRequest(timeout=0.5, readers=[reader])
            while not self.stopEvent.isSet():
                try:
                    card = self.cardrequest.waitforcardevent()
                    if card != self.card:
                        if not card:
                            self.observer.removed()
                        else:
                            self.observer.inserted(card[0])
                    self.card = card
                    self.initializedEvent.set()
                except Exception as e:
                    print >> sys.stderr, "Connection error:", e

    def __init__(self, reader):
        self.monitoring = Connection.Monitoring(self, reader)
        self.monitoring.start()
        while not self.monitoring.initializedEvent.isSet():
            sleep(0.1)

    def inserted(self, card):
        global card_connected
        global command_index
        global iccid
        select_mf_apdu_command = [0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]
        select_iccid_elementary_file = [
            0x00, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]
        read_binary_command = [0x00, 0xB0, 0x00, 0x00, 0x0A]
        self.__connection = card.createConnection()
        self.__connection.connect()
        self.__connection.transmit(select_mf_apdu_command)
        self.__connection.transmit(select_iccid_elementary_file)
        response, _, _ = self.__connection.transmit(
            read_binary_command)
        iccid = map(lambda x: "{:02x}".format(
            (x & 0x0F) << 4 | (x & 0xF0) >> 4), response)
        iccid = ''.join(iccid)
        card_connected = True
        command_index = 0
        print("Card ICCID: %s" % iccid)

    def removed(self):
        global card_connected
        global adm_verify
        self.__connection = None
        card_connected = False
        adm_verify = False
        print("Card removed")

    def send(self, apdu, show_sent=True):
        if not self.__connection:
            raise Exception("Card not connected")

        if show_sent:
            print(">> %s" % toHexString(apdu))

        data, sw1, sw2 = self.__connection.transmit(apdu)

        # print output and data
        print("<< %02X %02X%s" %
              (sw1, sw2, ", %d bytes" % len(data) if data else ""))
        if data:
            bytes = [toHexString(data[i:i+8])
                     for i in range(0, len(data), 8)]
            print("\n".join(["   "+"  ".join(bytes[i:i+4])
                             for i in range(0, len(bytes), 4)]))

        # return response
        return data + [sw1, sw2]

    def close(self):
        self.monitoring.stopEvent.set()
        self.connection = None


def hexByteToInt(byte):
    try:
        return int(byte, 16)
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError("Input error at %s" % str(e)[-4:])
        else:
            raise


def parse(line):
    apdu = []
    line, _, output = line.partition('>')
    line = line.split(' ')
    for part in line:
        if len(part) % 2 == 0:
            apdu.extend([hexByteToInt(part[2*i:2*i+2])
                         for i in range(int(len(part)/2))])
        elif len(part) == 1:
            apdu.append(hexByteToInt(part))
        else:
            raise ValueError("Input error at: '%s'" % part)

    output = output.strip()
    return apdu, output or None


def select_reader(name=None, index=None):
    readers_all = readers()
    if index is None:
        for reader in readers_all:
            if name in str(reader):
                return reader
        raise Exception("Unknown reader %s" % name)
    else:
        if index < len(readers_all):
            return readers_all[index]
        else:
            raise Exception("Unknown reader number #%d" % index)


def verify_adm_command(adm):
    global adm_verify
    adm_ascii_format = '3'.join([adm[i:i+1] for i in range(0, len(adm), 1)])
    command = "0020000a08" + "3" + adm_ascii_format
    apdu, output = parse(command)
    sw1, sw2 = connection.send(apdu)
    result = sw1 + sw2
    if result == 144:
        adm_verify = True
    else:
        raise AdmError('ADM not verified')


def build_adm_dictionary(iccid_adm_filename):
    iccid_adm_dictionary = {}
    with open("iccid_adm.txt") as f:
        for line in f:
            (iccid, adm) = line.split()
            iccid_adm_dictionary[iccid] = adm
    return iccid_adm_dictionary


def parse_apdu_commands(apdu_list_filename):
    apdu_commands = [line.rstrip('\n') for line in open(apdu_list_filename)]
    return apdu_commands


def update_completed():
    print('\a')
    print("[*]Update Completed")


def error_handle(reason):
    global card_connected
    print(reason + iccid)
    print('\a')
    sleep(0.25)
    print('\a')
    card_connected = False


if __name__ == "__main__":

    reader = None

    # Check TTY interactivity
    mode = os.fstat(0).st_mode
    interactive = not (stat.S_ISFIFO(mode) or stat.S_ISREG(mode))

    # Welcome message
    if interactive:
        import readline
        print ("""

Insert the card, and the ICCID will show,
after '[*]Update Completed' message and Beep sound, insert the next card.

""")

    iccid_adm_filename = os.path.join(
        os.path.abspath(os.getcwd()), "iccid_adm.txt")
    iccid_adm_dictionary = build_adm_dictionary(iccid_adm_filename)

    apdu_list_filename = os.path.join(os.path.abspath(
        os.getcwd()), "apdu_commands.txt")
    apdu_commands = parse_apdu_commands(apdu_list_filename)

    try:
        if not reader:
            reader = select_reader(index=0)
        elif reader.isdigit():
            reader = select_reader(index=int(reader))
        else:
            reader = select_reader(reader)

        connection = Connection(reader)

    except Exception as e:
        print >> sys.stderr, str(e)
        sys.exit(1)

    try:
        while True:

            if card_connected and command_index < len(apdu_commands):

                if not adm_verify:
                    try:
                        adm = iccid_adm_dictionary.get(iccid, "")
                        verify_adm_command(adm)
                    except ValueError:
                        reason = "ICCID not found in the database, iccid : "
                        error_handle(reason)
                        continue
                    except AdmError:
                        reason = "The ADM is not verified for ICCID : "
                        error_handle(reason)
                        continue
                command = apdu_commands[command_index]
                try:
                    apdu, _ = parse(command)
                    connection.send(apdu)
                    command_index += 1
                    if command_index == len(apdu_commands):
                        update_completed()

                except Exception as e:
                    print >> sys.stderr, error(
                        e, command_index if not interactive else None)

    except (KeyboardInterrupt, EOFError):
        if interactive:
            print
        connection.close()
        sys.exit()
