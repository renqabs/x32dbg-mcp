from typing import TypedDict, Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from x32dbg import Debugger

# Module related classes
class ModuleInfo:
    def __init__(self, debugger):
        self.debugger = debugger

    # Accept integer type parameters passed in
    def get_module_info(self, decimal_address, info_type):
        try:
            ref = self.debugger.script_runcmd_ex("mod.{}({})".
            	format(info_type, hex(decimal_address)))
            return ref if ref is not None else False
        except Exception:
            return False

    def base(self, decimal_address):
        return self.get_module_info(decimal_address, "base")

    def party(self, decimal_address):
        return self.get_module_info(decimal_address, "party")

    def size(self, decimal_address):
        return self.get_module_info(decimal_address, "size")

    def hash(self, decimal_address):
        return self.get_module_info(decimal_address, "hash")

    def entry(self, decimal_address):
        return self.get_module_info(decimal_address, "entry")

    def system(self, decimal_address):
        return self.get_module_info(decimal_address, "system")

    def user(self, decimal_address):
        return self.get_module_info(decimal_address, "user")

    def main(self):
        return self.get_module_info(0, "main")

    def rva(self, decimal_address):
        return self.get_module_info(decimal_address, "rva")

    def offset(self, decimal_address):
        return self.get_module_info(decimal_address, "offset")

    def isexport(self, decimal_address):
        return self.get_module_info(decimal_address, "isexport")


# Memory related classes
class MemoryInfo:
    def __init__(self, debugger):
        self.debugger = debugger

    def get_memory_info(self, decimal_address, info_type):
        try:
            ref = self.debugger.script_runcmd_ex("mem.{}({})".
                format(info_type, hex(decimal_address)))
            return ref if ref is not None else False
        except Exception:
            return False

    def valid(self, decimal_address):
        return self.get_memory_info(decimal_address, "valid")

    def base(self, decimal_address):
        return self.get_memory_info(decimal_address, "base")

    def size(self, decimal_address):
        return self.get_memory_info(decimal_address, "size")

    def iscode(self, decimal_address):
        return self.get_memory_info(decimal_address, "iscode")

    def decodepointer(self, decimal_address):
        return self.get_memory_info(decimal_address, "decodepointer")

    def bswap(self, decimal_address):
        return self.debugger.script_runcmd_ex("bswap({})".format(decimal_address))

    def readbyte(self, decimal_address):
        return self.debugger.script_runcmd_ex("ReadByte({})".format(decimal_address))

    def readword(self, decimal_address):
        return self.debugger.script_runcmd_ex("ReadWord({})".format(decimal_address))

    def readdword(self, decimal_address):
        return self.debugger.script_runcmd_ex("ReadDword({})".format(decimal_address))

    def readqword(self, decimal_address):
        return self.debugger.script_runcmd_ex("ReadQword({})".format(decimal_address))

    def readptr(self, decimal_address):
        return self.debugger.script_runcmd_ex("ReadPtr({})".format(decimal_address))

    def firstchance(self):
        return self.debugger.script_runcmd_ex("ex.firstchance()")

    def addr(self):
        return self.debugger.script_runcmd_ex("ex.addr()")

    def code(self):
        return self.debugger.script_runcmd_ex("ex.code()")

    def flags(self):
        return self.debugger.script_runcmd_ex("ex.flags()")

    def infocount(self):
        return self.debugger.script_runcmd_ex("ex.infocount()")

    def info(self, decimal_address):
        return self.debugger.script_runcmd_ex("ex.info({})".format(decimal_address))


# Global debugger and module info instances
dbg: Debugger | None = None
module: ModuleInfo | None = None
mem: MemoryInfo | None = None
mcp = FastMCP("x32dbg-mcp", log_level="ERROR")
DEBUGGER_IP = "127.0.0.1"
DEBUGGER_PORT = 6589

@mcp.tool()
def connect_debugger():
    """Connect to the x32dbg debugger"""
    global dbg, module,mem
    dbg = Debugger(address=DEBUGGER_IP, port=DEBUGGER_PORT)
    if dbg.connect():
        module = ModuleInfo(dbg)
        mem = MemoryInfo(dbg)
        return {"status": "connected", "success": True}
    return {"status": "failed to connect", "success": False}


@mcp.tool()
def disconnect_debugger()->bool:
    """Disconnect from the x32dbg debugger"""
    global dbg
    if dbg:
        dbg.close_connect()
        return True
    return False

@mcp.tool()
def debug_run()->bool:
    """Continue debugging"""
    global dbg
    if dbg:
        dbg.debug_run()
        return True
    return False

@mcp.tool()
def debug_pause()->bool:
    """Pause debugging"""
    global dbg
    if dbg:
        dbg.debug_pause()
        return True
    return False

@mcp.tool()
def debug_stop()->bool:
    """Stop debugging"""
    global dbg
    if dbg:
        dbg.debug_stop()
        return True
    return False

@mcp.tool()
def debug_step_into()->bool:
    """Step into"""
    global dbg
    if dbg:
        return dbg.debug_stepin()
    return False

@mcp.tool()
def debug_step_over()->bool:
    """Step over"""
    global dbg
    if dbg:
        return dbg.debug_stepover()
    return False

@mcp.tool()
def debug_step_out()->bool:
    """Step out"""
    global dbg
    if dbg:
        return dbg.debug_stepout()
    return False

@mcp.tool()
def debug_setcount(action:Annotated[str,Field(description="action, choice of [stepout, stepin, stepover, run, pause, stop, wait]")],
                   count: Annotated[int,Field(description="count of step")])->bool:
    """Set the debug action and count"""
    global dbg
    if dbg:
        return dbg.debug_setcount(action,count)
    return False

class ModuleMeta(TypedDict):
    Base: int
    Entry: str
    Name: str
    Path: str
    size: int

@mcp.tool()
def get_module()->list[ModuleMeta]|bool:
    """Get the Module Info"""
    global dbg
    if dbg:
        return dbg.get_module()
    return False


@mcp.tool()
def get_register(register_name: Annotated[str,Field(description="The name of the register (eip, eax, ebx, ecx, edx, esi, edi, esp, ebp)")]) -> str | None:
    """
    Get the value of a CPU register.
    Returns:Hexadecimal string representation of the register value
    """
    global dbg
    if not dbg:
        return None
    if register_name.lower() not in ['eip', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
        return None
    return str(dbg.get_register(register_name))


@mcp.tool()
def set_register(register_name: Annotated[str,Field(description="The name of the register (eip, eax, ebx, ecx, edx, esi, edi, esp, ebp)")],
                 value: Annotated[int,Field(description="value")]) -> bool:
    """
    Get the value of a CPU register.
    Returns:True if the register was set successfully, False otherwise
    """
    global dbg
    if not dbg:
        return False
    if register_name.lower() not in ['eip', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
        return False
    return dbg.set_register(register_name,value)

@mcp.tool()
def get_flag(flag_name: Annotated[str,Field(description="The name of the flag (zf, cf, sf, pf, af, df, of, if, tf)")]) -> bool | None:
    """
    Get the value of a CPU flag.
    Returns:Boolean value for the flag
    """
    global dbg
    if not dbg:
        return None

    if flag_name.lower() not in ['zf', 'cf', 'sf', 'pf', 'af', 'df', 'of', 'if', 'tf']:
        return None
    return dbg.get_flag_register(flag_name)

@mcp.tool()
def set_flag(flag_name: Annotated[str,Field(description="The name of the flag (zf, cf, sf, pf, af, df, of, if, tf)")],
             value: Annotated[bool,Field(description="value")]) -> bool:
    """
    Get the value of a CPU flag.
    Returns:True if the flag was set successfully, False otherwise
    """
    global dbg
    if not dbg:
        return False

    if flag_name.lower() not in ['zf', 'cf', 'sf', 'pf', 'af', 'df', 'of', 'if', 'tf']:
        return False
    return dbg.set_flag_register(flag_name, value)


class ModuleData(TypedDict):
    party: bool
    base: str
    size: str
    hash: str
    entry: str
    system: bool
    user: bool
    rva: str
    foa: str


def hex_str_to_int(hex_str: str) -> int|str:
    """Convert a hexadecimal string to an integer."""
    try:
        return int(hex_str, 16)
    except ValueError as e:
        return f"Error parsing hexadecimal string: {e}"

@mcp.tool()
def get_module_info(address:Annotated[str,Field(description="hexadecimal address")])->ModuleData|bool|str:
    """Obtain the module information where the destination address is located"""
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return int_address
    global module, dbg
    if not module or not dbg:
        return False

    result = {
        "party": module.party(int_address),
        "base": hex(module.base(int_address)),
        "size": hex(module.size(int_address)),
        "hash": hex(module.hash(int_address)),
        "entry": hex(module.entry(int_address)),
        "system": module.system(int_address),
        "user": module.user(int_address),
        "rva": hex(module.rva(int_address)),
        "foa": hex(module.offset(int_address)),
    }
    return result


def bypass_check_of_isdebug_present()->bool:
    peb = dbg.get_peb_address(dbg.get_process_id())
    return dbg.set_memory_byte(peb + 2, 0)

def long_to_ulong(inter,is_64 = False):
    if is_64 == False:
        return inter & ((1 << 32) - 1)
    else:
        return inter & ((1 << 64) - 1)

def ulong_to_long(inter,is_64 = False):
    if is_64 == False:
        return (inter & ((1 << 31) - 1)) - (inter & (1 << 31))
    else:
        return (inter & ((1 << 63) - 1)) - (inter & (1 << 63))


class CallStackInfo(TypedDict):
    stack_id: str
    ret_address: str
    module_base: str
    module_name: str
    module_path: str

@mcp.tool()
def get_call_stack(depth:Annotated[int,Field(description="depth")]=10)-> list[CallStackInfo|None]:
    """Get the Call Stack"""
    global dbg
    global mem
    call_stack = []
    module_list = []
    if dbg:
        module_list = dbg.get_module()
    for index in range(0,depth):
        stack_address = dbg.peek_stack(index)
        if stack_address <= 0:
            mod_base = 0
        else:
            mod_base = dbg.get_base_from_address(long_to_ulong(stack_address))
        if mod_base > 0 and len(module_list) > 0:
            for x in module_list:
                if mod_base == x.get("Base") and mem.iscode(stack_address):
                    call_stack.append({
                        "stack_id": str(index),
                        "ret_address": hex(stack_address),
                        "module_base": hex(mod_base),
                        "module_name": x.get('Name'),
                        "module_path": x.get('Path')
                    })
    return call_stack

@mcp.tool()
def memory_readbyte(address: Annotated[str,Field(description="hexadecimal address")]) -> str|bool|None:
    """Read a byte from memory"""
    global mem
    if not mem:
        return None
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return int_address
    return mem.readbyte(address)

@mcp.tool()
def memory_readword(address: Annotated[str,Field(description="hexadecimal address")]) -> str|bool|None:
    """Read a word from memory"""
    global mem
    if not mem:
        return None
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return int_address
    return mem.readword(address)

@mcp.tool()
def memory_readdword(address: Annotated[str,Field(description="hexadecimal address")]) -> str|bool|None:
    """Read a dword from memory"""
    global mem
    if not mem:
        return None
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return int_address
    return mem.readdword(address)


class BreakpointInfo(TypedDict):
    bpx_type: int
    address: str
    enabled: int
    single_shoot: int
    active: int
    name: str
    mod: str
    slot: int
    hit_count: int
    fast_resume: int
    silent: int
    break_condition: str
    log_text: str
    log_condition: str
    command_text: str
    command_condition: str

@mcp.tool()
def get_breakpoints()-> list[BreakpointInfo]|None:
    """Get All Breakpoints"""
    global dbg
    if not dbg:
        return None
    bp_list = dbg.get_breakpoint()
    for bp in bp_list:
        bp['Address'] = hex(bp['Address'])
    return bp_list

@mcp.tool()
def set_breakpoint(address: Annotated[str,Field(description="hexadecimal address")])-> bool|str:
    """Set a breakpoint"""
    global dbg
    if not dbg:
        return False
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return int_address
    return dbg.set_breakpoint(int_address)


@mcp.tool()
def set_breakpoint_by_name(name: Annotated[str,Field(description="function name")])-> bool:
    """Set a breakpoint by the function name"""
    global dbg
    if not dbg:
        return False
    dll_name, func_name = name.split(".")
    if dll_name and func_name:
        if len(dll_name) > 0 and len(func_name) > 0:
            bp_addr = dbg.get_module_proc_addr(dll_name, func_name)
            return dbg.set_breakpoint(bp_addr)
    return False

@mcp.tool()
def delete_breakpoint(address: Annotated[str,Field(description="hexadecimal address")])-> bool:
    """Delete a breakpoint by address"""
    global dbg
    if not dbg:
        return False
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return False
    return dbg.delete_breakpoint(int_address)

@mcp.tool()
def set_hardware_breakpoint(address:Annotated[str,Field(description="hexadecimal address")],
                            type:Annotated[int,Field(description="hardware breakpoint type, HardwareAccess=0, HardwareWrite=1, HardwareExecute=2")] = 0)-> bool:
    """
    Set a hardware breakpoint
    Returns:True if the hardware breakpoint was set successfully, False otherwise.
    """
    global dbg
    if not dbg:
        return False
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return False
    return dbg.set_hardware_breakpoint(int_address,type)

@mcp.tool()
def set_hardware_breakpoint_by_name(
        name:Annotated[str,Field(description="function name")],
        type:Annotated[int,Field(description="hardware breakpoint type, HardwareAccess=0, HardwareWrite=1, HardwareExecute=2")] = 0)-> bool|str:
    """
    Set a hardware breakpoint by function name
    Returns:True if the hardware breakpoint was set successfully, False otherwise.
    """
    global dbg
    if not dbg:
        return False
    dll_name, func_name = name.split(".")
    if dll_name and func_name:
        if len(dll_name) > 0 and len(func_name) > 0:
            bp_addr = dbg.get_module_proc_addr(dll_name, func_name)
            return dbg.set_hardware_breakpoint(bp_addr, type)
    return False

@mcp.tool()
def delete_hardware_breakpoint(address:Annotated[str,Field(description="hexadecimal address")])-> bool:
    """Delete a hardware breakpoint by address"""
    global dbg
    if not dbg:
        return False
    int_address = hex_str_to_int(address)
    if isinstance(int_address, str):
        return False
    return dbg.delete_hardware_breakpoint(int_address)

def main():
    print("Starting the x32dbg MCP server!")
    mcp.run(transport="stdio")

def test():
    if connect_debugger():
        eip = get_register('eip')
        mod_info = get_module_info(eip)
        print(mod_info)
        call_stacks = get_call_stack(30)
        for call_stack in call_stacks:
            print(call_stack)



if __name__ == "__main__":
    main()


