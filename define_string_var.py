import re

import binaryninja
from binaryninja.plugin import PluginCommand
from binaryninja.log import log_alert, log_debug, log_info

MAX_STRING_LENGTH = 256

_RE_REPLACE_UNDERSCORE = re.compile("[^a-zA-Z0-9]")
_RE_COMPRESS_UNDERSCORE = re.compile("__+")


def escaped_output(str):
    return '\n'.join([s.encode("string_escape") for s in str.split('\n')])


def get_address_from_inst(bv, addr):
    inst = None
    try:
        bbs = bv.get_basic_blocks_at(addr)
        if bbs:
            inst = bbs[0].function.get_low_level_il_at(addr)
    except IndexError:
        inst = None

    if inst is not None:
        log_debug("got inst: {!r}".format(inst))
        if inst.src:
            if inst.src.value:
                if inst.src.value.value:
                    return inst.src.value.value
    else:
        return None


def get_string_varname(s):
    varname = "str_"
    varname += _RE_REPLACE_UNDERSCORE.sub("_", s)
    varname = _RE_COMPRESS_UNDERSCORE.sub("_", varname)
    return varname


def define_str_var(bv, addr):
    a = get_address_from_inst(bv, addr)
    if not a:
        a = addr
    data = bv.read(a, MAX_STRING_LENGTH)
    if not data:
        log_alert("failed to read from 0x{:x}".format(a))
    if b"\x00" in data:
        length = data.find("\x00") + 1
    else:
        log_info("not a null-terminated string: {!r}".format(data))
        log_alert("doesn't look like a null-terminated-string")
        return
    varname = get_string_varname(data[:length])
    t = bv.parse_type_string("char {}[{}]".format(varname, length))
    bv.define_user_data_var(a, t[0])
    sym = binaryninja.types.Symbol('DataSymbol', a, varname[:21], varname)
    bv.define_user_symbol(sym)


# Register commands for the user to interact with the plugin
PluginCommand.register_for_address("Define string variable",
                                   "Define string variable", define_str_var)
