import binaryninja
from binaryninja import (PluginCommand, get_text_line_input)
from binaryninja.types import (Symbol, SymbolType)
from binaryninja.log import (log_debug, log_info, log_warn)

from struct import unpack

_SGX_ECALL_TABLE_SYMBOL = "g_ecall_table"

_SGX_ECALL_TYPE_NAME = "sgx_ecall_table_entry"
_SGX_ECALL_TYPE_STRING = """
struct {
    void* fptr;
    void* _null;
} sgx_ecall_table_entry;
"""

_SGX_ECALLT_BNSYMBOL = 'ecall_table'
_SGX_ECALLTS_BNSYMBOL = 'ecall_table_size'


def find_ecall_table_heuristic(bv):
    ptr_s = bv.arch.address_size
    ptr = 'I' if ptr_s == 4 else 'Q'

    found = []
    try:
        sections = ('.rdata', '.rodata')
        for s in sections:
            if s in bv.sections:
                sectionname = s
                break

        start = bv.sections[sectionname].start
        length = bv.sections[sectionname].end - start
        data = bv.read(start, length)

        i = 5 * ptr_s
        while i < len(data):
            nu = data.index(b"\0" * ptr_s, i)
            if not nu:
                break
            i = nu + 1
            if (nu % ptr_s) == 0:
                nr, *ec = unpack(f"<{ptr * 5}",
                                 data[nu - 2 * ptr_s:nu + 3 * ptr_s])
                if (2 <= nr < 300 and ec[1] == ec[3] == 0
                        and ec[0] != 0 != ec[2]):
                    found.append(start + nu - 2 * ptr_s)
    except Exception as e:
        log_warn(f"exception thrown: {e}")
    return found


def find_ecall_table(bv):
    ptr_s = bv.arch.address_size

    ecall_type = None

    found = []
    if _SGX_ECALL_TABLE_SYMBOL in bv.symbols:
        log_debug("found ecall table symbol")
        found.append(bv.symbols[_SGX_ECALL_TABLE_SYMBOL])
    else:
        log_debug("doing heuristic search")
        found = find_ecall_table_heuristic(bv)

    ecall_type = None
    if found:
        if _SGX_ECALL_TYPE_NAME in bv.types:
            ecall_type = bv.types[_SGX_ECALL_TYPE_NAME]
        else:
            ecall_type, name = bv.parse_type_string(_SGX_ECALL_TYPE_STRING)
            assert name == _SGX_ECALL_TYPE_NAME, "unexpected type name?"
            bv.define_user_type(name, ecall_type)

    tag_book = bv.tag_types['Bookmarks']
    for f in found:
        log_info(f"{f} ({type(f)})")
        addr = None
        if isinstance(f, int):
            log_info(f"found ecall table at {f:#x}")
            addr = f
        elif isinstance(f, binaryninja.types.Symbol):
            log_info(f"found ecall table at {f}")
            addr = f.address
        else:
            raise NotImplementedError(f"Can't handle type: {f} ({type(f)})")

        tag = bv.create_tag(tag_book, '')
        bv.add_user_data_tag(addr, tag)

        if ptr_s == 4:
            bv.define_data_var(addr, bv.parse_type_string('uint32_t x')[0])
            if not isinstance(f, Symbol):
                s = Symbol(SymbolType.DataSymbol, addr, "ecall_table_size")
                bv.define_user_symbol(s)

            ecalls_count = unpack('I', bv.read(addr, 4))[0]
        else:
            bv.define_data_var(addr, bv.parse_type_string('uint64_t x')[0])
            if not isinstance(f, Symbol):
                s = Symbol(SymbolType.DataSymbol, addr, "ecall_table_size")
                bv.define_user_symbol(s)

            ecalls_count = unpack('Q', bv.read(addr, 8))[0]

        log_info(f"identified {ecalls_count} ecalls")

        table_addr = addr + ptr_s
        table_type, _ = bv.parse_type_string(
            f"struct {_SGX_ECALL_TYPE_NAME} ecall_table[{ecalls_count}]")

        bv.define_data_var(table_addr, table_type)
        s = Symbol(SymbolType.DataSymbol, table_addr, "ecall_table")
        bv.define_user_symbol(s)


PluginCommand.register("SGX\\find ecall table",
                       "In a SGX binary, try to identify the ecall table",
                       find_ecall_table)
