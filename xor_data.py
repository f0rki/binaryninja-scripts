from binaryninja import (PluginCommand, get_text_line_input)
from binaryninja.log import (log_debug, log_info)


def get_int_input(text):
    x = get_text_line_input(text, "integer value")
    if x is None:
        return x
    try:
        key = int(x)
    except ValueError:
        key = int(x, 16)
    return key


def xor_string(s, k, n=None):
    if n is None:
        n = len(s)
    x = []
    for i, c in enumerate(s):
        if i == n:
            break
        x.append(ord(c) ^ k)
    return "".join(map(chr, x))


def xor_data(bv, addr, key, length):
    log_info("starting xor at address 0x{:x}".format(addr))
    data = bv.read(addr, length)
    log_debug("got data {!r}".format(data))
    xdata = xor_string(data, key, length)
    log_debug("decrypted data {!r}".format(xdata))
    bv.write(addr, xdata)
    return xdata


def xor_data_ask(bv, addr):
    log_info("starting xor at address 0x{:x}".format(addr))
    key = get_int_input("xor key")
    if not key:
        return
    length = get_int_input("length")
    if not length:
        return
    xor_data(bv, addr, key, length)


PluginCommand.register_for_address("XOR data @ addr", "XOR data @ addr",
                                   xor_data_ask)
