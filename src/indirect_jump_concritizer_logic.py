from pathlib import Path
import subprocess
from loguru import logger
from sympy import false
from cons import RUNNING_MODE
from singleton import Singleton
import re

addr2line_process = None
from functools import lru_cache

class IndirectJumpConcritizer(metaclass=Singleton):
    def __init__(self, args = None) -> None:
        self.setup_done = False
        self.resolved = {}
        self.cache_get_called_functions = {}
        self.args = args
        self.counter_result = {}
        pass

    @lru_cache
    def parse_function_name(self, func_name):
        package, interface, fun = None, None, None
        fun_parts = func_name.split(".")

        match len(fun_parts):
            case _ if len(fun_parts) >= 3:
                package = fun_parts[-3]
                interface = fun_parts[-2]
                fun = fun_parts[-1]
                if package == "":
                    package = interface
                    interface = ""

            case 2:
                package = fun_parts[-2]
                fun = fun_parts[-1]

            case 1:
                fun = fun_parts[-1]

        if package and package.startswith("z2f"):
            package = package.replace("z2f", "")
        return package, interface, fun

    def evaluate_function(self, fun, package, interface, function):
        # local function call idk why this will be called but eh
        if len(package) < 1 and len(interface) < 1:
            return (False, "both package and interface is empty")

        if "stub" in fun.name:
            return (False, "stub in name for function")

        fun_package, fun_interface, fun_fun = self.parse_function_name(fun.name)
        if not fun_package and not fun_interface and not fun_fun:
            return (False, "could not parse func name into parts")

            # if (package == "" or package == fun_package):
            #     if fun_fun and fun_fun != function:
            #         return (False, "function name does not match")

            #     # if fun_interface and interface not in fun_interface:
            #     #     return (False, "interface not matching")

            #     return (True, "function matches and package matches or empty")
            # else:
            #     # if interface[0].istitle():
            #         # interface with block letter means public interface (Reader) only has one method Read, anyone who implements this function can be a candidate
        if fun_fun and fun_fun == function:
            return (True, "package does not match but interface is title and function matches")

        return (False, "default case :(")

    def setup(self, project, cfg_fast):
        if not self.setup_done:
            self.project = project
            self.cfg_fast = cfg_fast
            cmds = ["addr2line", "-e", project.filename]
            self.addr2line_process = subprocess.Popen(
                cmds,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            self.setup_done = True

    def call_go_ast(self, filepath, line_number):
        numbers = re.findall(r'\d+', line_number)
        filepath = filepath.strip()
        line_number = numbers[0]
        if (filepath, line_number) not in self.resolved or len(
            self.resolved[(filepath, line_number)]
        ) == 0:
            project_root = Path(__file__).resolve().parent.parent
            go_ast_cmd = [
                "/usr/local/go/bin/go",
                "run",
                f"{project_root}/src/ast_getter/src/ast_getter.go",
                "-file",
                filepath,
                "-line",
                line_number,
            ]
            logger.trace(f"Calling go ast with {go_ast_cmd}")
            result = subprocess.run(go_ast_cmd, stdout=subprocess.PIPE)
            splitwise = str(result.stdout, encoding="UTF-8").split(";")
            self.resolved[(filepath, line_number)] = []
            for split in splitwise:
                if len(split) > 0:
                    package, interface, function = split.split(",")
                    self.resolved[(filepath, line_number)].append((package.strip(), interface.strip(), function.strip()))
            if len(self.resolved[(filepath, line_number)]) == 0:
                logger.error(f"no result for {" ".join(go_ast_cmd)}")
                return ("", "", "", " ".join(go_ast_cmd))
        return self.resolved[(filepath, line_number)].pop() + (" ".join(go_ast_cmd), )


    @lru_cache
    def find_matching_function(self, package, interface, function):
        addresses = []
        for fun in self.cfg_fast.kb.functions.values():
            f_package, f_interface, f_function = self.parse_function_name(fun.name)
            if f_package == package and f_interface == interface and f_function == function:
                logger.trace(
                    f"[{package}, {interface}, {function}] Found exact function:  {fun.name} @ {hex(fun.addr)}"
                )
                return [fun.addr]
            matched, reason = self.evaluate_function(fun, package, interface, function)
            if matched:
                logger.trace(
                    f"[{package}, {interface}, {function}] [{reason}] Found valid function:  {fun.name} @ {hex(fun.addr)}"
                )
                addresses.append(fun.addr)

        return addresses

    @lru_cache
    def get_called_functions(self, addr: int):
        """This function will use the addr2line process to get the corresponding source file and then utilize the function called to resolve the function, along with the ABI

        Args:
            addr (int): _description_

        Returns:
            str: _description_
        """
        if self.args and self.args.mode == RUNNING_MODE.REGULAR:
            return None
        
        local_go_src = "/home/ubuntu/gcc-10.5.0/libgo/go/"

        actual_address = addr  # - proj.loader.min_addr

        ## calls addr2line to get the filename and the location
        self.addr2line_process.stdin.write(hex(actual_address)[2:] + "\n")
        self.addr2line_process.stdin.flush()
        addr2line_output = self.addr2line_process.stdout.readline()
        filename, line_number = addr2line_output.split(":")
        logger.trace(f"[{hex(addr)}] addr2line output: {addr2line_output}")
        package = interface = function = ''
        try:
            if "/go/" in filename:
                filepath = local_go_src + filename.split("/go/")[1]
                package, interface, function, go_cmd = self.call_go_ast(filepath.strip(), line_number.strip())
                logger.trace(f"[{hex(addr)}] Matching for {package}, {interface}, {function}")
            else:
                logger.trace(f"[{hex(addr)}] Not a go file, addr2line output: {addr2line_output}")
                return None
        except Exception as e:
            # logger.exception(e)
            logger.exception(f"Could not get funciton address for {hex(addr)} -- addr2line output -- {addr2line_output}")
            return None
        addresses = self.find_matching_function( package, interface, function)

        if len(addresses) == 0:
            logger.info(
                f"[{hex(addr)}] [{package}, {interface}, {function}] No Valid function"
            )
            logger.info(f"Go Command: {go_cmd}")
            return None
        elif len(addresses) >= 1:
            return addresses
            # self.counter_result[counter] = addresses.pop()
            # self.cache_get_called_functions[addr] = addresses
            # logger.info(
            #     f"[{hex(addr)}] [{package}, {interface}, {function}] Found multiple function returning {self.cfg_fast.functions.get_by_addr(self.counter_result[counter]).name}"
            # )
            # return self.counter_result[counter]
        return addresses[0]
