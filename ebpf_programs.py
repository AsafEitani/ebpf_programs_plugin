from volatility3.framework import constants, renderers, interfaces, symbols, objects, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from typing import Optional, Type
import logging
from datetime import datetime
import binascii
from copy import copy
import time

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

vollog = logging.getLogger(__name__)

ROOTKIT_HELPERS = ["bpf_probe_write_user", "bpf_override_return", "bpf_skb_store_bytes", "bpf_skb_pull_data", "bpf_send_signal"]
BPF_PROG_TYPE_NAMES = {
    0: "BPF_PROG_TYPE_UNSPEC",
    1: "BPF_PROG_TYPE_SOCKET_FILTER",
    2: "BPF_PROG_TYPE_KPROBE",
    3: "BPF_PROG_TYPE_SCHED_CLS",
    4: "BPF_PROG_TYPE_SCHED_ACT",
    5: "BPF_PROG_TYPE_TRACEPOINT",
    6: "BPF_PROG_TYPE_XDP",
    7: "BPF_PROG_TYPE_PERF_EVENT",
    8: "BPF_PROG_TYPE_CGROUP_SKB",
    9: "BPF_PROG_TYPE_CGROUP_SOCK",
    10: "BPF_PROG_TYPE_LWT_IN",
    11: "BPF_PROG_TYPE_LWT_OUT",
    12: "BPF_PROG_TYPE_LWT_XMIT",
    13: "BPF_PROG_TYPE_SOCK_OPS",
    14: "BPF_PROG_TYPE_SK_SKB",
    15: "BPF_PROG_TYPE_CGROUP_DEVICE",
    16: "BPF_PROG_TYPE_SK_MSG",
    17: "BPF_PROG_TYPE_RAW_TRACEPOINT",
    18: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    19: "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    20: "BPF_PROG_TYPE_LIRC_MODE2",
    21: "BPF_PROG_TYPE_SK_REUSEPORT",
    22: "BPF_PROG_TYPE_FLOW_DISSECTOR",
    23: "BPF_PROG_TYPE_CGROUP_SYSCTL",
    24: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    25: "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    26: "BPF_PROG_TYPE_TRACING",
    27: "BPF_PROG_TYPE_STRUCT_OPS",
    28: "BPF_PROG_TYPE_EXT",
    29: "BPF_PROG_TYPE_LSM",
    30: "BPF_PROG_TYPE_SK_LOOKUP",
    31: "BPF_PROG_TYPE_SYSCALL"
}


def convert_bpf_prog_type_value(type_value):
    return BPF_PROG_TYPE_NAMES[type_value]

class radix_tree_iter:
    def __init__(self):
        self.index = 0
        self.next_index = 0
        self.tags = 0
        self.node = None

# Constants
XA_CHUNK_SHIFT = 6 # Can also be 4 if CONFIG_BASE_SMALL is defined in compilation
XA_CHUNK_SIZE = 1 << XA_CHUNK_SHIFT
XA_MAX_MARKS = 3
XA_MARK_LONGS = (XA_CHUNK_SIZE + 8 - 1) // 8
BPF_TAG_SIZE = 8
RADIX_TREE_MAP_SHIFT = XA_CHUNK_SHIFT
RADIX_TREE_MAP_SIZE = 1 << RADIX_TREE_MAP_SHIFT
RADIX_TREE_MAP_MASK = RADIX_TREE_MAP_SIZE-1
RADIX_TREE_ITER_TAG_MASK = 15
RADIX_TREE_ITER_TAGGED = 16
RADIX_TREE_ITER_CONTIG = 32
RADIX_TREE_ENTRY_MASK = 3
RADIX_TREE_INTERNAL_NODE = 2
BITS_PER_LONG = 64
RADIX_TREE_TAG_LONGS = ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)
ROOT_TAG_SHIFT = 26
INT_MAX = 0x7FFFFFFFFFFFFFFF


# Radix Tree Functions
def __ffs(word):
    for i in range(64):
        if word & (1 << i):
            return i
    return None

def radix_tree_chunk_size(iterator):
    return iterator.next_index - iterator.index

def shift_maxindex(shift):
    return (RADIX_TREE_MAP_SIZE << shift) - 1

def node_maxindex(node):
    return shift_maxindex(node.shift)

def __radix_tree_iter_add(iterator, slots):
    return iterator.index + slots

def radix_tree_is_internal_node(ptr):
    return (ptr & RADIX_TREE_ENTRY_MASK) == RADIX_TREE_INTERNAL_NODE

def new_pointer_to_object(ptr, address, object):
    context = ptr._context
    vmlinux = context.modules['kernel']
    symbol_table = vmlinux.symbol_table_name
    return context.object(
        symbol_table + constants.BANG + object,
        layer_name=vmlinux.layer_name,
        offset=address,
    )

def new_pointer_by_offset(ptr, offset):
    context = ptr._context
    vmlinux = context.modules['kernel']
    symbol_table = vmlinux.symbol_table_name
    for map in ptr._vol.maps:
        if isinstance(map, interfaces.objects.ObjectInformation):
            obj_info = copy(map)
            obj_info._dict['offset'] += obj_info._dict['size'] * offset
            return objects.Pointer(context, symbol_table + constants.BANG + "pointer", obj_info, ptr._data_format)


def entry_to_node(ptr):
    return new_pointer_to_object(ptr, ptr & ~RADIX_TREE_INTERNAL_NODE, "xa_node")

def node_to_entry(ptr):
    return new_pointer_to_object(ptr, ptr | RADIX_TREE_INTERNAL_NODE, "xa_node")

def test_bit(nr, addr):
    return bool(addr & (1 << nr))

def root_tag_get(root, tag):
    return int(root.xa_flags & (1 << (tag + ROOT_TAG_SHIFT)))

def tag_get(node, tag, offset):
    return test_bit(offset, node.tags[tag])

def radix_tree_load_root(root):
    node = root.xa_head
    nodep = copy(node)

    if radix_tree_is_internal_node(node):
        node = entry_to_node(node)
        maxindex = node_maxindex(node)
        return nodep, maxindex, node.shift + RADIX_TREE_MAP_SHIFT

    return nodep, 0, 0

def radix_tree_iter_init(iterator, start: int):
    iterator.index = 0
    iterator.next_index = start

def set_iter_tags(iterator, node, offset, tag):
    tag_long = offset // BITS_PER_LONG
    tag_bit = offset % BITS_PER_LONG

    if node is None:
        iterator.tags = 1
        return

    iterator.tags = node.tags[tag][tag_long] >> tag_bit

    if tag_long < RADIX_TREE_TAG_LONGS - 1:
        if tag_bit:
            iterator.tags |= node.tags[tag][tag_long + 1] << (BITS_PER_LONG - tag_bit)
        iterator.next_index = __radix_tree_iter_add(BITS_PER_LONG)

def radix_tree_next_slot(slot, iterator, flags):
    """
    radix_tree_next_slot - find next slot in chunk

    @slot:      pointer to current slot
    @iter:      pointer to iterator state
    @flags:     RADIX_TREE_ITER_*, should be constant
    Returns:    pointer to next slot, or None if there no more left

    This function updates @iterator.index in the case of a successful lookup.
    For tagged lookup, it also eats @iterator.tags.

    There are several cases where 'slot' can be passed in as None to this
    function.  These cases result from the use of radix_tree_iter_resume() or
    radix_tree_iter_retry().  In these cases we don't end up dereferencing
    'slot' because either:
    a) we are doing tagged iteration and iterator.tags has been set to 0, or
    b) we are doing non-tagged iteration, and iterator.index and iterator.next_index
       have been set up so that radix_tree_chunk_size() returns 1 or 0.
    """

    if flags & RADIX_TREE_ITER_TAGGED:
        iterator.tags >>= 1
        if not iterator.tags:
            return None
        if iterator.tags & 1:
            iterator.index = __radix_tree_iter_add(iterator, 1)
            return new_pointer_by_offset(slot, 1)
        if not (flags & RADIX_TREE_ITER_CONTIG):
            offset = __ffs(iterator.tags)
            iterator.tags >>= offset
            offset += 1
            iterator.index = __radix_tree_iter_add(iterator, offset)
            return new_pointer_by_offset(slot, offset)
    else:
        count = radix_tree_chunk_size(iterator) - 1
        while count > 0:
            slot = new_pointer_by_offset(slot, 1)
            iterator.index = __radix_tree_iter_add(iterator, 1)
            if slot:  # Assuming *slot is equivalent to checking if slot is not None
                return slot
            if flags & RADIX_TREE_ITER_CONTIG:
                # forbid switching to the next chunk
                iterator.next_index = 0
                break
            count -= 1
    return None


def radix_tree_find_next_bit(node, tag, offset):
    """
    radix_tree_find_next_bit - find the next set bit in a memory region

    @node: where to begin the search
    @tag: the tag index
    @offset: the bitnumber to start searching at

    Unrollable variant of find_next_bit() for constant size arrays.
    Tail bits starting from size to roundup(size, BITS_PER_LONG) must be zero.
    Returns next bit offset, or size if nothing found.
    """
    addr = node.tags[tag]

    if offset < RADIX_TREE_MAP_SIZE:
        addr += offset // BITS_PER_LONG
        tmp = addr.dereference() >> (offset % BITS_PER_LONG)
        if tmp:
            return __ffs(tmp) + offset
        offset = (offset + BITS_PER_LONG) & ~(BITS_PER_LONG - 1)

        while offset < RADIX_TREE_MAP_SIZE:
            addr += 1
            tmp = addr.dereference()
            if tmp:
                return __ffs(tmp) + offset
            offset += BITS_PER_LONG

    return RADIX_TREE_MAP_SIZE


def radix_tree_descend(parent, index):
    offset = (index >> parent.shift) & RADIX_TREE_MAP_MASK
    entry = parent.slots[offset]

    return entry, offset


def radix_tree_next_chunk(root, iterator, flags):
    """
    radix_tree_next_chunk - find next chunk of slots for iteration

    @root:   radix tree root
    @iter:   iterator state
    @flags:  RADIX_TREE_ITER_* flags and tag index
    Returns: pointer to chunk first slot, or None if iteration is over
    """
    tag = flags & RADIX_TREE_ITER_TAG_MASK
    restart = True
    if (flags & RADIX_TREE_ITER_TAGGED) and not root_tag_get(root, tag):
        return None

    index = iterator.next_index
    if not index and iterator.index:
        return None

    while restart:
        restart = False
        child, maxindex, ret = radix_tree_load_root(root)

        if index > maxindex:
            return None
        if not child:
            return None

        if not radix_tree_is_internal_node(child):
            iterator.index = index
            iterator.next_index = maxindex + 1
            iterator.tags = 1
            iterator.node = None
            return root.xa_head

        condition = True
        while condition:
            node = entry_to_node(child)
            child, offset = radix_tree_descend(node, index)

            if (flags & RADIX_TREE_ITER_TAGGED and tag_get(node, tag, offset)) or \
                (not (flags & RADIX_TREE_ITER_TAGGED) and not child):
                # Hole detected
                if flags & RADIX_TREE_ITER_CONTIG:
                    return None
                if (flags & RADIX_TREE_ITER_TAGGED):
                    offset = radix_tree_find_next_bit(node, tag, offset + 1)
                else:
                    offset += 1
                    while offset < RADIX_TREE_MAP_SIZE:
                        slot = node.slots[offset]
                        if slot:
                            break
                        offset += 1
                index &= ~node_maxindex(node)
                index += offset << node.shift
                # Overflow after ~0UL
                if not index:
                    return None
                if offset == RADIX_TREE_MAP_SIZE:
                    restart = True
                    break
                child = node.slots[offset]

            if not child:
                restart = True
                break
            if int(child) == RADIX_TREE_INTERNAL_NODE:
                break
            condition = node.shift and radix_tree_is_internal_node(child)
        # Update the iterator state
        iterator.index = (index & ~node_maxindex(node)) | offset
        iterator.next_index = (index | node_maxindex(node)) + 1
        iterator.node = node

        if flags & RADIX_TREE_ITER_TAGGED:
            set_iter_tags(iterator, node, offset, tag)
        if offset >= node.slots.count:
            return None

        return node.slots[offset]

def radix_tree_for_each_slot(root, iterator, start):
    """
    radix_tree_for_each_slot - iterate over non-empty slots

    @root: the radix_tree_root pointer
    @iter: the radix_tree_iter pointer
    @start: iteration starting index

    Yields (slot, iterator.index) tuple for each non-empty slot in the radix tree.
    """
    slot = radix_tree_iter_init(iterator, start)
    if not slot:
        slot = radix_tree_next_chunk(root, iterator, 0)
    while slot:
        # do something with slot
        yield slot, iterator.index
        slot = radix_tree_next_slot(slot, iterator, 0)
        if not slot:
            slot = radix_tree_next_chunk(root, iterator, 0)


def idr_for_each(idr):
    iterator = radix_tree_iter()
    base = idr.idr_base

    for slot, index in radix_tree_for_each_slot(idr.idr_rt, iterator, 0):
        id = iterator.index + base
        if id > int(INT_MAX):
            break
        yield slot


# Class

class EbpfPrograms(interfaces.plugins.PluginInterface):
    """Lists the loaded eBPF programs."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(
                name="name",
                description="Filter on specific program name",
                element_type=str,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump BPF bytecode",
                optional=True,
                default=False,
            ),
        ]

    def __init__(self, config, *args, **kwargs):
        super().__init__(config, *args, **kwargs)
        self._name = self.__class__.__name__.lower()

    @classmethod
    def dump_bpf(
            cls,
            open_method: Type[interfaces.plugins.FileHandlerInterface],
            address: int,
            data: bytes,
            prefix: str = "",
            name: str = "UnreadableBPFName",
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Extracts the complete data for a BPF program as a FileInterface

        Args:
            open_method: class for constructing output files
            address: the address of the BPF program
            data: the bytecode of the function
            prefix: a prefix to add to the filenames
            name: the name of the BPF program


        Returns:
            An open FileHandlerInterface object containing the complete data for the BPF program or None in the case of failure
        """
        if not name:
            name = "UnreadableBPFName"
        try:
            file_handle = open_method(
                "{}{}.{:#x}.dmp".format(
                    prefix,
                    name,
                    address,
                )
            )
            file_handle.write(data)
        except (
                IOError,
                exceptions.VolatilityException,
                OverflowError,
                ValueError,
        ) as excp:
            vollog.debug(f"Unable to dump BPF at offset {address}: {excp}")
            return None
        return file_handle


    def _generator(self):
        start = time.time()
        c = 0
        ch = []
        global BITS_PER_LONG
        vmlinux = self.context.modules[self.config['kernel']]

        if symbols.symbol_table_is_64bit(self.context, vmlinux.symbol_table_name):
            BITS_PER_LONG = 64
            if has_capstone:
                mode = capstone.CS_MODE_64
        else:
            BITS_PER_LONG = 32
            if has_capstone:
                mode = capstone.CS_MODE_32

        timekeeper = vmlinux.object_from_symbol("tk_core").timekeeper
        if timekeeper:
            real_time = timekeeper.xtime_sec
            boot_time = real_time - timekeeper.ktime_sec
        else:
            boot_time = 0

        bpf_prog_ptr = vmlinux.object_from_symbol("prog_idr")
        for slot in idr_for_each(bpf_prog_ptr):
            if not slot:
                continue
            bpf_prog = entry_to_node(slot).cast('bpf_prog')

            probe_type = convert_bpf_prog_type_value(bpf_prog.type)
            tag = binascii.hexlify(bytearray(bpf_prog.tag)).decode('ascii')
            jited_bytes_len = bpf_prog.jited_len

            load_time = None
            name = None
            full_name = None
            if bpf_prog.aux:
                aux = bpf_prog.aux.dereference()
                if aux.ksym and aux.ksym.name:
                    full_name = utility.array_to_string(aux.ksym.name)
                    name = full_name[full_name.index(tag)+len(tag)+1:]
                load_time = aux.load_time / 1000000000
                load_time = renderers.conversion.unixtime_to_datetime(boot_time + int(load_time))

            # name filtering
            if self.config["name"] and name not in self.config["name"]:
                continue

            data = b''
            rootkit = False
            used_helpers = set()
            file_output = "Disabled"
            if bpf_prog.bpf_func:
                data = self.context.layers.read(vmlinux.layer_name, bpf_prog.bpf_func, jited_bytes_len)
                if self.config["dump"]:
                    file_handle = self.dump_bpf(
                        self.open,
                        int(bpf_prog.bpf_func),
                        data,
                        name=name,
                    )
                    file_output = "Error outputting file"
                    if file_handle:
                        file_handle.close()
                        file_output = file_handle.preferred_filename

                # Disassemble and analyse helpers
                try:
                    if has_capstone:
                        md = capstone.Cs(capstone.CS_ARCH_X86, mode)

                        for address, size, mnemonic, op_str in md.disasm_lite(data, bpf_prog.bpf_func):
                            if mnemonic.lower() == "call":
                                used_helpers.update(vmlinux.get_symbols_by_absolute_location(int(op_str,16)))
                except:
                    vollog.debug(f"Unable to disassemble BPF program {name} at address {bpf_prog.bpf_func}")

            used_helpers = [helper[helper.index(constants.BANG)+1:] for helper in used_helpers]
            ch += used_helpers

            # Check if any rootkit helpers are used by the ebpf program
            for helper in ROOTKIT_HELPERS:
                if helper in used_helpers:
                    rootkit = True
                    break

            c += 1
            yield (0, (name, full_name, probe_type, jited_bytes_len, load_time, ','.join(used_helpers),
                       rootkit, file_output))


    def run(self):
        return renderers.TreeGrid([('Name', str), ('Full Name', str), ('Type', str), ('Jited Bytes Length', int),
                                   ('Load Time', datetime), ("Used Helpers", str),
                                   ("Rootkit Behavior", bool), ("Dumped Filename", str)], self._generator())
