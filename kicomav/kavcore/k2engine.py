# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import contextlib
import os
from importlib.machinery import SourceFileLoader
from io import StringIO
import datetime
import types
import mmap
import glob
import re
import shutil
import struct
import zipfile
import hashlib
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import deque

try:
    from . import k2timelib
    from . import k2file
    from . import k2const
    from . import k2security
except ImportError:
    import k2timelib
    import k2file
    import k2const
    import k2security


# ---------------------------------------------------------------------
# Define engine error message
# ---------------------------------------------------------------------
class EngineKnownError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# -------------------------------------------------------------------------
# Engine class
# -------------------------------------------------------------------------
class Engine:
    # ---------------------------------------------------------------------
    # __init__(self, verbose=False)
    # Initialize the class
    # Argument: verbose - Debug mode
    # ---------------------------------------------------------------------
    def __init__(self, verbose=False):
        self.verbose = verbose  # Debug mode

        self.plugins_path = None  # Plugin path
        self.temp_path = None  # Temporary folder class
        self.kmdfiles = []  # List of kmd files with priority
        self.kmd_modules = []  # Loaded modules in memory

        # Worker pool for parallel scanning (cached workers)
        self.worker_pool = []  # List of EngineInstance
        self.worker_pool_size = 0  # Current pool size

        # The latest time value of the plugin engine
        # Initial value is set to 1980-01-01
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)

        # Remove all temporary files created by KicomAV (initialize the operating system's temporary folder)
        k2file.K2Tempfile().removetempdir()

        self.__set_temppath()  # Initialize temporary folder

    # ---------------------------------------------------------------------
    # __del__(self)
    # Terminate the class
    # ---------------------------------------------------------------------
    def __del__(self):
        # Cleanup worker pool first
        self.cleanup_worker_pool()

        # Remove all temporary files created by KicomAV
        self.temp_path.removetempdir()

        with contextlib.suppress(OSError):
            shutil.rmtree(self.temp_path.temp_path)

    # ---------------------------------------------------------------------
    # set_plugins(self, plugins_path)
    # Prepare to load the plugin engine from the given path
    # Argument: plugins_path - Plugin engine path
    # Return: Success or not
    # ---------------------------------------------------------------------
    def set_plugins(self, plugins_path, callback_fn=None):
        # Save the plugin path
        self.plugins_path = plugins_path

        # Get the plugin list from kicom.lst
        ret = self.__get_plugin_list(os.path.join(plugins_path, "kicom.lst"))

        if not ret:  # No plugin files to load
            return False

        if self.verbose:
            print("[*] kicom.lst :")
            print(f"   {self.kmdfiles}")

        # Load plugin files in priority order
        for plugin_name in self.kmdfiles:
            plugin_path = os.path.join(plugins_path, f"{plugin_name}.py")
            try:
                # Use full module path to ensure consistent module identity
                # This prevents duplicate module loading when plugins use
                # "from kicomav.plugins import ..." imports
                full_module_name = f"kicomav.plugins.{plugin_name}"
                module = SourceFileLoader(full_module_name, plugin_path).load_module()
                # CWE-73 safe deletion - remove .pyc files in plugins directory
                pyc_path = os.path.join(plugins_path, f"{plugin_name}.pyc")
                with contextlib.suppress(OSError, k2security.SecurityError):
                    k2security.safe_remove_file(pyc_path, plugins_path)

                if module:  # Memory loading successful
                    self.kmd_modules.append(module)
                    # Read the time value of the plugin engine from file modification time
                    self.__get_last_plugin_build_time(plugin_path)
                elif isinstance(callback_fn, types.FunctionType):
                    callback_fn(plugin_name)
            except (IOError, ImportError, Exception) as e:
                # Plugin failed to load (missing dependency, syntax error, etc.)
                if isinstance(callback_fn, types.FunctionType):
                    callback_fn(plugin_name)
                pass

        # Get the latest time value from the malware pattern
        fl = glob.glob1(plugins_path, "*.n??")
        for fname in fl:
            with contextlib.suppress(IOError):
                fname = os.path.join(plugins_path, fname)
                buf = open(fname, "rb").read(12)
                if buf[:4] == b"KAVS":
                    sdate = k2timelib.convert_date(struct.unpack("<H", buf[8:10])[0])
                    stime = k2timelib.convert_time(struct.unpack("<H", buf[10:12])[0])

                    t_datetime = datetime.datetime(
                        sdate[0], sdate[1], sdate[2], stime[0], stime[1], stime[2], tzinfo=datetime.timezone.utc
                    )

                    self.max_datetime = max(self.max_datetime, t_datetime)

        if self.verbose:
            print("[*] kmd_modules :")
            print(f"   {self.kmd_modules}")
            print(f"[*] Last updated {self.max_datetime.ctime()} UTC")

        return True

    # ---------------------------------------------------------------------
    # __set_temppath(self)
    # Set the given temporary folder
    # ---------------------------------------------------------------------
    def __set_temppath(self):
        # Set the temporary folder
        self.temp_path = k2file.K2Tempfile()

    # ---------------------------------------------------------------------
    # create_instance(self)
    # Create an instance of the antivirus engine
    # ---------------------------------------------------------------------
    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.temp_path, self.max_datetime, self.verbose)
        return ei if ei.create(self.kmd_modules) else None

    # ---------------------------------------------------------------------
    # create_instance_for_worker(self)
    # Create an independent instance for parallel worker threads
    # Each worker needs its own plugin instances to avoid thread conflicts
    # ---------------------------------------------------------------------
    def create_instance_for_worker(self):
        # Create new temp path for this worker
        worker_temp_path = k2file.K2Tempfile()
        ei = EngineInstance(self.plugins_path, worker_temp_path, self.max_datetime, self.verbose)
        return ei if ei.create(self.kmd_modules) else None

    # ---------------------------------------------------------------------
    # init_worker_pool(self, size)
    # Initialize worker pool with specified size (called once, reused across scans)
    # Argument: size - Number of workers to create
    # ---------------------------------------------------------------------
    def init_worker_pool(self, size):
        if self.worker_pool_size >= size:
            return  # Pool already initialized with enough workers

        # Create additional workers if needed
        for _ in range(size - self.worker_pool_size):
            worker_inst = self.create_instance_for_worker()
            if worker_inst:
                self.worker_pool.append(worker_inst)

        self.worker_pool_size = len(self.worker_pool)

    # ---------------------------------------------------------------------
    # get_workers_from_pool(self, count, options)
    # Get workers from pool and initialize them for scanning
    # Argument: count - Number of workers needed
    #           options - Scan options to apply
    # Return: List of initialized worker instances
    # ---------------------------------------------------------------------
    def get_workers_from_pool(self, count, options):
        # Ensure pool has enough workers
        if self.worker_pool_size < count:
            self.init_worker_pool(count)

        workers = []
        for i in range(min(count, self.worker_pool_size)):
            worker = self.worker_pool[i]
            worker.set_options(options)
            # Reset worker state for new scan
            if not hasattr(worker, "_pool_initialized") or not worker._pool_initialized:
                worker.init()
                worker._pool_initialized = True
            else:
                # Reset result counters for reuse
                worker.reset_result()
            workers.append(worker)

        return workers

    # ---------------------------------------------------------------------
    # cleanup_worker_pool(self)
    # Cleanup all workers in the pool
    # ---------------------------------------------------------------------
    def cleanup_worker_pool(self):
        for worker in self.worker_pool:
            try:
                worker.uninit()
            except Exception:
                pass
        self.worker_pool = []
        self.worker_pool_size = 0

    # ---------------------------------------------------------------------
    # __get_last_plugin_build_time(self, plugin_path)
    # Store the latest value of the build time of the plugin engine
    # Argument: plugin_path - Plugin file path
    # ---------------------------------------------------------------------

    def __get_last_plugin_build_time(self, plugin_path):
        try:
            mtime = os.path.getmtime(plugin_path)
            t_datetime = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
            self.max_datetime = max(self.max_datetime, t_datetime)
        except OSError:
            pass

    # ---------------------------------------------------------------------
    # __get_plugin_list(self, plugin_list_file)
    # Get the loading priority of the plugin engine
    # Argument: plugin_list_file - Full path of the kicom.lst file
    # Return: Success or not
    # ---------------------------------------------------------------------
    def __get_plugin_list(self, plugin_list_file):
        plugin_files = []  # Priority list

        try:
            with open(plugin_list_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:  # If the line is not empty
                        plugin_files.append(line)
        except IOError:
            return False

        if len(plugin_files):  # If there is at least one in the priority list, success
            self.kmdfiles = plugin_files  # Keep variable name for compatibility
            return True
        else:  # If there is nothing in the priority list, failure
            return False


# -------------------------------------------------------------------------
# EngineInstance class
# -------------------------------------------------------------------------
class EngineInstance:
    # ---------------------------------------------------------------------
    # __init__(self, plugins_path, temp_path, max_datetime, verbose=False)
    # Initialize the class
    # Argument: plugins_path - Plugin engine path
    #           temp_path    - Temporary folder class
    #           max_datetime - Latest time value of the plugin engine
    #           verbose      - Debug mode
    # ---------------------------------------------------------------------
    def __init__(self, plugins_path, temp_path, max_datetime, verbose=False):
        self.verbose = verbose  # Debug mode

        self.plugins_path = plugins_path  # Plugin engine path
        self.temp_path = temp_path  # Temporary folder class
        self.max_datetime = max_datetime  # Latest time value of the plugin engine

        # Build rules_paths from environment variables
        self.rules_paths = {
            "system": os.environ.get("SYSTEM_RULES_BASE", "").strip() or None,
            "user": os.environ.get("USER_RULES_BASE", "").strip() or None,
        }

        self.options = {}  # Options
        self.set_options()  # Set default options

        self.kavmain_inst = []  # KavMain instance of all plugins

        self.update_info = []  # List of compressed files for final treatment

        self.result = {}
        self.identified_virus = set()  # Used to count unique viruses
        self.set_result()  # Initialize virus scan results

        self.quarantine_name = {}  # Used to move files to the virus name folder when moving to the quarantine folder

        self.disinfect_callback_fn = None  # Virus treatment callback function
        self.update_callback_fn = None  # Final virus compression callback function
        self.quarantine_callback_fn = None  # Virus isolation callback function

        self.disable_path = re.compile(r"/<\w+>")

        self.whitelist = []  # Whitelist for false positive exclusion

    # ---------------------------------------------------------------------
    # create(self, kmd_modules)
    # Create an instance of the antivirus engine.
    # Argument: kmd_modules - List of KMD modules loaded into memory
    # Return: Success or not
    # ---------------------------------------------------------------------
    def create(self, kmd_modules):  # Create an instance of the antivirus engine
        for mod in kmd_modules:
            try:
                t = mod.KavMain()  # Create an instance of the KavMain class for each plugin
                self.kavmain_inst.append(t)
            except AttributeError:  # KavMain class does not exist
                continue

        if not len(self.kavmain_inst):
            return False

        if self.verbose:
            print("[*] Count of KavMain : %d" % (len(self.kavmain_inst)))

        return True

    # ---------------------------------------------------------------------
    # init(self, callback_fn)
    # Initialize the entire plugin engine.
    # Argument: callback_fn - Callback function (optional)
    # Return: Success or not
    # ---------------------------------------------------------------------
    def init(self, callback_fn=None):
        # self.kavmain_inst is not the final instance.
        # init initialization command must be executed to register only normal plugins.
        t_kavmain_inst = []  # Final instance list

        if self.verbose:
            print("[*] KavMain.init() :")

        for inst in self.kavmain_inst:
            try:
                # Call the init function of the plugin engine with rules_paths dict
                ret = inst.init(self.rules_paths, self.options["opt_verbose"])

                if not ret:  # Success
                    t_kavmain_inst.append(inst)

                    if self.verbose:
                        print("    [-] %s.init() : %d" % (inst.__module__, ret))
                elif isinstance(callback_fn, types.FunctionType):
                    callback_fn(inst.__module__)
            except AttributeError:
                continue

        self.kavmain_inst = t_kavmain_inst  # Register the final KavMain instance

        if len(self.kavmain_inst):  # If there is at least one KavMain instance, success
            self.__load_whitelist()  # Load whitelist for false positive exclusion
            if self.verbose:
                print(f"[*] Count of KavMain.init() : {len(self.kavmain_inst)}")
            return True
        else:
            return False

    # ---------------------------------------------------------------------
    # __load_whitelist(self)
    # Load whitelist from SYSTEM_RULES_BASE/whitelist.txt for false positive exclusion
    # ---------------------------------------------------------------------
    def __load_whitelist(self):
        self.whitelist = []

        # Get whitelist path from rules_paths
        system_rules_path = self.rules_paths.get("system")
        if not system_rules_path:
            return  # No SYSTEM_RULES_BASE configured, whitelist disabled

        whitelist_path = os.path.join(system_rules_path, "whitelist.txt")

        try:
            with open(whitelist_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        self.whitelist.append(line)

            if self.verbose and self.whitelist:
                print(f"[*] Whitelist loaded: {len(self.whitelist)} entries")
        except IOError:
            pass  # Whitelist file is optional

    # ---------------------------------------------------------------------
    # __is_whitelisted(self, vname)
    # Check if malware name is in the whitelist
    # Argument: vname - Malware name to check
    # Return: True if whitelisted, False otherwise
    # ---------------------------------------------------------------------
    def __is_whitelisted(self, vname):
        import fnmatch

        for pattern in self.whitelist:
            # Support wildcard patterns (e.g., YARA.yaraex.*)
            if fnmatch.fnmatch(vname, pattern):
                return True
        return False

    # ---------------------------------------------------------------------
    # uninit(self)
    # Terminate the entire plugin engine.
    # ---------------------------------------------------------------------
    def uninit(self):
        if self.verbose:
            print("[*] KavMain.uninit() :")

        for inst in self.kavmain_inst:
            try:
                ret = inst.uninit()
                if self.verbose:
                    print(f"    [-] {inst.__module__}.uninit() : {ret}")
            except AttributeError:
                continue

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Get the plugin engine information.
    # Return: List of plugin engine information
    # ---------------------------------------------------------------------
    def getinfo(self):
        ginfo = []  # Store plugin engine information

        if self.verbose:
            print("[*] KavMain.getinfo() :")

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.verbose:
                    print(f"    [-] {inst.__module__}.getinfo() :")
                    for key in ret.keys():
                        print(f"        - {key} : {ret[key]}")
            except AttributeError:
                continue

        return ginfo

    # ---------------------------------------------------------------------
    # listvirus(self, *callback)
    # Get the list of viruses that the plugin engine can detect/cure.
    # Argument: callback - Callback function (optional)
    # Return: List of viruses (empty if callback function is used)
    # ---------------------------------------------------------------------
    def listvirus(self, *callback):
        vlist = []  # List of viruses that can be detected/cured

        argc = len(callback)  # Check the number of arguments

        if argc == 0:  # No arguments
            cb_fn = None
        elif argc == 1:  # Check if the callback function exists
            cb_fn = callback[0]
        else:  # Too many arguments
            return []

        if self.verbose:
            print("[*] KavMain.listvirus() :")

        for inst in self.kavmain_inst:
            try:
                ret = inst.listvirus()

                # If the callback function exists, call the callback function
                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(inst.__module__, ret)
                else:  # If the callback function does not exist, accumulate the virus list and return
                    vlist += ret

                if self.verbose:
                    print(f"    [-] {inst.__module__}.listvirus() :")
                    for vname in ret:
                        print(f"        - {vname}")
            except AttributeError:
                continue

        return vlist

    # ---------------------------------------------------------------------
    # scan(self, filename, *callback)
    # Request virus scanning from the plugin engine.
    # Argument: filename - Name of the file or folder to be scanned for viruses
    #           callback - Callback function for displaying the scan results
    # Return: 0 - Success
    #          1 - Virus scanning forcibly terminated using Ctrl+C
    #         -1 - Too many callback functions
    # ---------------------------------------------------------------------
    def scan(self, filename, *callback):
        from kicomav.plugins import kernel

        # If scanning a file one by one, the self.update_info information is accumulated due to compression
        self.update_info = []
        scan_callback_fn = None  # Virus scanning callback function

        move_master_file = False  # Whether to isolate the master file
        t_master_file = ""  # Master file

        # Virus scanning results
        ret_value = {
            "filename": "",  # File name
            "result": False,  # Whether a virus is found
            "virus_name": "",  # Name of the found virus
            "virus_id": -1,  # Virus ID
            "engine_id": -1,  # ID of the plugin engine that found the virus
        }

        with contextlib.suppress(IndexError):
            scan_callback_fn = callback[0]
            self.disinfect_callback_fn = callback[1]
            self.update_callback_fn = callback[2]
            self.quarantine_callback_fn = callback[3]

        # 1. Register the file in the virus scanning target list
        file_info = k2file.FileStruct(filename)
        file_scan_list = [file_info]

        # Scan subfolders only once
        is_sub_dir_scan = True

        while len(file_scan_list):
            try:
                t_file_info = file_scan_list.pop(0)  # Get the file to be scanned
                real_name = t_file_info.get_filename()

                # If it is a folder, register only the internal file list
                if os.path.isdir(real_name):
                    # Remove os.sep for processing folders
                    real_name = os.path.abspath(real_name)

                    # Call the callback function or create the scan return value
                    ret_value["result"] = False  # No virus found
                    ret_value["filename"] = real_name  # File name
                    ret_value["file_struct"] = t_file_info  # File name
                    ret_value["scan_state"] = kernel.NOT_FOUND  # No virus found

                    self.result["Folders"] += 1  # Count the number of folders

                    if self.options["opt_list"]:  # Whether to output all lists
                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    if is_sub_dir_scan:
                        # Add the files in the folder to the virus scanning target list
                        flist = glob.glob1(real_name, "*")
                        tmp_flist = []

                        for rfname in flist:
                            rfname = os.path.join(real_name, rfname)
                            tmp_info = k2file.FileStruct(rfname)
                            tmp_flist.append(tmp_info)

                        file_scan_list = tmp_flist + file_scan_list

                    if self.options["opt_nor"]:  # Whether to search for subfolders
                        is_sub_dir_scan = False  # Do not search for subfolders
                elif (
                    os.path.isfile(real_name) or t_file_info.is_archive()
                ):  # Is the target a file? Is it a decompression target?
                    self.result["Files"] += 1  # Count the number of files

                    # If it is a compressed file, decompress it
                    if real_name == "":  # If the actual file name does not exist, it is a compressed file
                        ret, ret_fi = self.unarc(t_file_info)
                        if ret:
                            t_file_info = ret_fi  # If the compressed result exists, replace the file information
                        elif ret_fi:  # Whether an error message exists
                            # Call the callback function or create the scan return value
                            ret_value["result"] = ret  # Whether a virus is found
                            ret_value["engine_id"] = -1  # Engine ID
                            ret_value["virus_name"] = ret_fi  # Replace with error message
                            ret_value["virus_id"] = -1  # Virus ID
                            ret_value["scan_state"] = kernel.ERROR  # Virus scan state
                            ret_value["file_struct"] = t_file_info  # File name

                            if self.options["opt_list"]:  # Whether to output all lists
                                self.call_scan_callback_fn(scan_callback_fn, ret_value)

                            continue

                    # Mode added to find abnormal termination files
                    if self.options["opt_debug"]:  # Whether in debugging mode
                        ret_value["result"] = False  # Whether a virus is found
                        ret_value["engine_id"] = -1  # Engine ID
                        ret_value["virus_name"] = "debug"  # Replace with error message
                        ret_value["virus_id"] = -1  # Virus ID
                        ret_value["scan_state"] = kernel.ERROR  # Virus scan state
                        ret_value["file_struct"] = t_file_info  # File name

                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    # 2. Format analysis
                    ff = self.format(t_file_info)

                    # Virus scan of the file
                    ret, vname, mid, scan_state, eid = self.__scan_file(t_file_info, ff)

                    if ret:  # Count the number of virus diagnoses
                        if scan_state == kernel.INFECTED:
                            self.result["Infected_files"] += 1
                        elif scan_state == kernel.SUSPECT:
                            self.result["Suspect_files"] += 1
                        elif scan_state == kernel.WARNING:
                            self.result["Warnings"] += 1

                        self.identified_virus.update([vname])

                    # Call the callback function or create the scan return value
                    ret_value["result"] = ret  # Whether a virus is found
                    ret_value["engine_id"] = eid  # Engine ID
                    ret_value["virus_name"] = vname  # Virus name
                    ret_value["virus_id"] = mid  # Virus ID
                    ret_value["scan_state"] = scan_state  # Virus scan state
                    ret_value["file_struct"] = t_file_info  # File name

                    # Check the isolation point?
                    if move_master_file and t_master_file != t_file_info.get_master_filename():
                        self.__arcclose()
                        self.__quarantine_file(t_master_file)
                        move_master_file = False

                    if ret_value["result"]:  # Whether a virus is found
                        t_master_file = t_file_info.get_master_filename()

                        # If a virus name is assigned to the quarantine folder, use it
                        if not self.quarantine_name.get(t_master_file, None):
                            self.quarantine_name[t_master_file] = ret_value["virus_name"]

                        action_type = self.call_scan_callback_fn(scan_callback_fn, ret_value)

                        if self.options["opt_move"] or self.options["opt_copy"]:
                            if t_file_info.get_additional_filename() == "":
                                # print ('move 1 :', t_master_file)
                                self.__arcclose()
                                self.__quarantine_file(t_master_file)
                                move_master_file = False
                            else:
                                move_master_file = True
                        else:  # Isolation option is applied before treatment option
                            if action_type == k2const.K2_ACTION_QUIT:  # Whether to terminate
                                return 0

                            d_ret = self.__disinfect_process(ret_value, action_type)

                            if d_ret and (
                                self.options["opt_dis"]
                                or action_type
                                in [
                                    k2const.K2_ACTION_DISINFECT,
                                    k2const.K2_ACTION_DELETE,
                                ]
                            ):
                                if os.path.exists(t_file_info.get_filename()):
                                    t_file_info.set_modify(True)
                                    file_scan_list = [t_file_info] + file_scan_list
                                else:
                                    # Final treatment of compressed files
                                    self.__update_process(t_file_info)
                    else:
                        # Final treatment of compressed files
                        self.__update_process(t_file_info)

                        # If the file has already been determined to be a virus
                        # There is no need to decompress it and look inside.
                        # If it is a compressed file, add it to the virus scanning target list
                        with contextlib.suppress(zipfile.BadZipfile):
                            arc_file_list = self.arclist(t_file_info, ff)
                            if len(arc_file_list):
                                file_scan_list = arc_file_list + file_scan_list

                        # Output the scan result
                        if self.options["opt_list"]:  # Whether to output all lists
                            self.call_scan_callback_fn(scan_callback_fn, ret_value)
            except KeyboardInterrupt:
                return 1  # Keyboard termination
            except k2const.PluginUnexpectedError:
                # Count plugin unexpected errors as IO errors
                self.result["IO_errors"] += 1
            except Exception:
                import traceback

                print(traceback.format_exc())

        self.__update_process(None, True)  # Final file cleanup

        # Check the isolation point?
        if move_master_file:
            self.__arcclose()
            self.__quarantine_file(t_master_file)
            move_master_file = False

        return 0  # Normal termination of virus scan

    # ---------------------------------------------------------------------
    # scan_parallel(self, filename, max_workers, k2_engine, *callback)
    # Request parallel virus scanning from the plugin engine.
    # Files are processed in parallel, but plugins run sequentially per file.
    # Argument: filename    - Name of the file or folder to be scanned
    #           max_workers - Maximum number of worker threads
    #           k2_engine   - Engine instance for creating worker instances
    #           callback    - Callback functions
    # Return: 0 - Success, 1 - Interrupted, -1 - Error
    # ---------------------------------------------------------------------
    def scan_parallel(self, filename, max_workers, k2_engine, *callback):
        from kicomav.plugins import kernel
        import signal
        import time
        import logging
        from queue import Queue, Empty
        from threading import Thread, Event

        scan_callback_fn = None
        self.update_info = []

        with contextlib.suppress(IndexError):
            scan_callback_fn = callback[0]
            self.disinfect_callback_fn = callback[1]
            self.update_callback_fn = callback[2]
            self.quarantine_callback_fn = callback[3]

        # Shared work queue and synchronization
        work_queue = Queue()
        result_lock = Lock()
        stop_event = Event()
        keyboard_interrupted = False
        producer_done = Event()

        # Callback queue for async callback execution (no lock needed)
        callback_queue = Queue()
        callback_done = Event()

        # Signal handler for Ctrl+C
        original_handler = signal.getsignal(signal.SIGINT)

        def signal_handler(signum, frame):
            nonlocal keyboard_interrupted
            keyboard_interrupted = True
            stop_event.set()
            callback_done.set()  # Signal callback thread to stop
            # Suppress logger warnings during shutdown
            logging.disable(logging.WARNING)

        signal.signal(signal.SIGINT, signal_handler)

        def callback_thread_fn():
            """Dedicated thread for callback execution - no lock needed"""
            while not callback_done.is_set() or not callback_queue.empty():
                try:
                    ret_value = callback_queue.get(timeout=0.1)
                    if ret_value is None:  # Poison pill
                        break
                    if not stop_event.is_set():
                        self.call_scan_callback_fn(scan_callback_fn, ret_value)
                except Empty:
                    continue
                except Exception:
                    pass

        # Worker-local results for lock-free counting
        worker_local_results = [
            {"Files": 0, "Infected_files": 0, "Suspect_files": 0, "Warnings": 0, "viruses": set()}
            for _ in range(max_workers)
        ]

        def worker_thread(worker_instance, worker_id, local_result):
            """Worker thread that processes files from queue"""
            while not stop_event.is_set():
                try:
                    # Increased timeout: 0.05s -> 0.2s (reduces CPU wake-ups by 4x)
                    # Still responsive to Ctrl+C within 200ms
                    file_path = work_queue.get(timeout=0.2)
                except Empty:
                    if producer_done.is_set() and work_queue.empty():
                        break
                    continue

                if file_path is None:  # Poison pill
                    work_queue.task_done()
                    break

                # Skip processing if interrupted
                if stop_event.is_set():
                    work_queue.task_done()
                    break

                try:
                    result = self._scan_file_with_archives(file_path, worker_instance, local_result)
                    # Skip callback if interrupted - use callback_queue instead of result_lock
                    if result and not stop_event.is_set():
                        self._process_parallel_result(result, scan_callback_fn, callback_queue)
                except Exception:
                    pass
                finally:
                    work_queue.task_done()

        def file_producer():
            """Multi-producer that parallelizes directory traversal"""
            from concurrent.futures import ThreadPoolExecutor, as_completed

            BATCH_SIZE = 100  # Batch size for reducing queue lock contention
            MAX_PRODUCERS = min(4, max_workers)  # Limit producer threads

            def scan_directory(dir_path):
                """Sub-producer for scanning a subdirectory tree"""
                file_batch = []
                scan_queue = deque([dir_path])

                while scan_queue and not stop_event.is_set():
                    current_path = scan_queue.popleft()

                    try:
                        with os.scandir(current_path) as entries:
                            for entry in entries:
                                if stop_event.is_set():
                                    break
                                if entry.is_dir():
                                    with result_lock:
                                        self.result["Folders"] += 1
                                    if not self.options.get("opt_nor", False):
                                        scan_queue.append(entry.path)
                                elif entry.is_file():
                                    file_batch.append(entry.path)
                                    if len(file_batch) >= BATCH_SIZE:
                                        for f in file_batch:
                                            work_queue.put(f)
                                        file_batch = []
                    except (OSError, PermissionError):
                        pass

                # Flush remaining files in batch
                for f in file_batch:
                    work_queue.put(f)

            # Process root path
            root_path = os.path.abspath(filename)

            if os.path.isfile(root_path):
                # Single file scan
                work_queue.put(root_path)
            elif os.path.isdir(root_path):
                # Directory scan with multi-producer
                with result_lock:
                    self.result["Folders"] += 1

                subdirs = []
                root_files = []

                try:
                    with os.scandir(root_path) as entries:
                        for entry in entries:
                            if entry.is_dir():
                                with result_lock:
                                    self.result["Folders"] += 1
                                subdirs.append(entry.path)
                            elif entry.is_file():
                                root_files.append(entry.path)
                except (OSError, PermissionError):
                    pass

                # Enqueue root-level files immediately
                for f in root_files:
                    work_queue.put(f)

                # Parallel directory traversal with sub-producers
                if subdirs and not self.options.get("opt_nor", False):
                    with ThreadPoolExecutor(max_workers=MAX_PRODUCERS) as producer_pool:
                        futures = [producer_pool.submit(scan_directory, d) for d in subdirs]
                        for future in as_completed(futures):
                            if stop_event.is_set():
                                break
                            try:
                                future.result()
                            except Exception:
                                pass

            producer_done.set()

            # Send poison pills to stop workers
            for _ in range(max_workers):
                work_queue.put(None)

        # Get worker instances from pool (main instance + pooled workers)
        # First scan initializes pool, subsequent scans reuse workers
        worker_instances = [self]
        pool_workers = k2_engine.get_workers_from_pool(max_workers - 1, self.options)
        worker_instances.extend(pool_workers)

        # Start worker threads with local result dictionaries
        workers = []
        for i, worker_inst in enumerate(worker_instances):
            t = Thread(target=worker_thread, args=(worker_inst, i, worker_local_results[i]), daemon=True)
            t.start()
            workers.append(t)

        # Start producer thread
        producer = Thread(target=file_producer, daemon=True)
        producer.start()

        # Start callback thread for async callback execution
        cb_thread = Thread(target=callback_thread_fn, daemon=True)
        cb_thread.start()

        try:
            # Poll with longer interval (0.1s -> 0.25s) to reduce CPU usage
            # Workers exit via poison pills, so we just wait for producer to finish
            while not stop_event.is_set():
                if not producer.is_alive() and work_queue.empty():
                    break
                time.sleep(0.25)

            # Wait for all workers to process remaining items
            # Using join with timeout for Ctrl+C responsiveness
            if not keyboard_interrupted:
                while not work_queue.empty() and not keyboard_interrupted:
                    time.sleep(0.1)

        finally:
            # Restore original signal handler
            signal.signal(signal.SIGINT, original_handler)

            stop_event.set()
            # Wait for workers to finish
            for w in workers:
                w.join(timeout=0.5)

            # Signal callback thread to stop and wait for it
            callback_done.set()
            callback_queue.put(None)  # Poison pill for callback thread
            cb_thread.join(timeout=2.0)

            # Aggregate worker-local results (lock-free during scan, single-threaded here)
            for local_result in worker_local_results:
                self.result["Files"] += local_result["Files"]
                self.result["Infected_files"] += local_result["Infected_files"]
                self.result["Suspect_files"] += local_result["Suspect_files"]
                self.result["Warnings"] += local_result["Warnings"]
                self.identified_virus.update(local_result["viruses"])

            # Aggregate Packed count from all workers
            # Each worker's arclist() increments its own result["Packed"]
            total_packed = sum(w.result.get("Packed", 0) for w in worker_instances)
            self.result["Packed"] = total_packed

            # Note: Pool workers are NOT uninitialized here - they're reused
            # Pool cleanup happens in Engine.cleanup_worker_pool()

            # Restore logger only if not interrupted
            # (interrupted case: workers may still be cleaning up)
            if not keyboard_interrupted:
                logging.disable(logging.NOTSET)

        return 1 if keyboard_interrupted else 0

    # ---------------------------------------------------------------------
    # _collect_files_for_parallel(self, filename)
    # Collect all top-level files for parallel processing
    # ---------------------------------------------------------------------
    def _collect_files_for_parallel(self, filename):
        files_to_scan = []
        file_info = k2file.FileStruct(filename)
        scan_queue = deque([file_info])

        while scan_queue:
            t_file_info = scan_queue.popleft()
            real_name = t_file_info.get_filename()

            if os.path.isdir(real_name):
                real_name = os.path.abspath(real_name)
                self.result["Folders"] += 1

                # Add files in directory
                if not self.options.get("opt_nor", False):
                    try:
                        with os.scandir(real_name) as entries:
                            for entry in entries:
                                tmp_info = k2file.FileStruct(entry.path)
                                scan_queue.append(tmp_info)
                    except (OSError, PermissionError):
                        pass
            elif os.path.isfile(real_name):
                files_to_scan.append(real_name)

        return files_to_scan

    # ---------------------------------------------------------------------
    # _scan_file_with_archives(self, filename, worker_instance, local_result)
    # Scan a single file including nested archives (sequential within worker)
    # IMPORTANT: Plugin execution order is maintained for malware detection
    # local_result: Worker-local counters (lock-free)
    # ---------------------------------------------------------------------
    def _scan_file_with_archives(self, filename, worker_instance, local_result):
        from kicomav.plugins import kernel

        results = []
        file_info = k2file.FileStruct(filename)
        file_scan_list = deque([file_info])

        while file_scan_list:
            t_file_info = file_scan_list.popleft()
            real_name = t_file_info.get_filename()

            if not os.path.isfile(real_name) and not t_file_info.is_archive():
                continue

            # Lock-free: update worker-local counter
            local_result["Files"] += 1

            # Handle archive extraction
            if real_name == "":
                ret, ret_fi = worker_instance.unarc(t_file_info)
                if ret:
                    t_file_info = ret_fi
                elif ret_fi:
                    continue

            # Format analysis (plugins run sequentially - order matters!)
            ff = worker_instance.format(t_file_info)

            # Virus scan (plugins run sequentially - order matters!)
            ret, vname, mid, scan_state, eid = worker_instance._EngineInstance__scan_file(t_file_info, ff)

            result = {
                "filename": t_file_info.get_filename(),
                "file_struct": t_file_info,
                "result": ret,
                "virus_name": vname,
                "virus_id": mid,
                "scan_state": scan_state,
                "engine_id": eid,
            }

            # Lock-free: update worker-local counters
            if ret:
                if scan_state == kernel.INFECTED:
                    local_result["Infected_files"] += 1
                elif scan_state == kernel.SUSPECT:
                    local_result["Suspect_files"] += 1
                elif scan_state == kernel.WARNING:
                    local_result["Warnings"] += 1
                local_result["viruses"].add(vname)

            results.append(result)

            # If not infected, check for nested archives (only if --arc option is set)
            if not ret and self.options.get("opt_arc", False):
                with contextlib.suppress(zipfile.BadZipfile, Exception):
                    arc_file_list = worker_instance.arclist(t_file_info, ff)
                    if arc_file_list:
                        # Packed count is already incremented inside arclist()
                        # Add to front for depth-first processing
                        for arc_file in reversed(arc_file_list):
                            file_scan_list.appendleft(arc_file)

        return results[0] if len(results) == 1 else results

    # ---------------------------------------------------------------------
    # _process_parallel_result(self, result, scan_callback_fn, callback_queue)
    # Process scan result and add to callback queue (no lock needed)
    # ---------------------------------------------------------------------
    def _process_parallel_result(self, result, scan_callback_fn, callback_queue):
        from kicomav.plugins import kernel

        if isinstance(result, list):
            for r in result:
                self._process_single_result(r, scan_callback_fn, callback_queue)
        else:
            self._process_single_result(result, scan_callback_fn, callback_queue)

    def _process_single_result(self, result, scan_callback_fn, callback_queue):
        from kicomav.plugins import kernel

        if not result or "file_struct" not in result:
            return

        fs = result.get("file_struct")
        rep_path = self.disable_path.sub("", fs.get_additional_filename())
        fs.set_additional_filename(rep_path)

        ret_value = {
            "filename": result.get("filename", ""),
            "result": result.get("result", False),
            "virus_name": result.get("virus_name", ""),
            "virus_id": result.get("virus_id", -1),
            "engine_id": result.get("engine_id", -1),
            "scan_state": result.get("scan_state", kernel.NOT_FOUND),
            "file_struct": fs,
        }

        # Add to callback queue - no lock needed (Queue is thread-safe)
        if ret_value["result"] or self.options.get("opt_list", False):
            callback_queue.put(ret_value)

    # ---------------------------------------------------------------------
    # call_scan_callback_fn(self, a_scan_callback_fn, ret_value)
    # When outputting the virus scan result, exclude the /<...> display.
    # Argument: a_scan_callback_fn - Callback function
    #         ret_value : Output target
    # Return: Return value of scan callback function
    # ---------------------------------------------------------------------
    def call_scan_callback_fn(self, a_scan_callback_fn, ret_value):
        if isinstance(a_scan_callback_fn, types.FunctionType):
            fs = ret_value["file_struct"]  # Output file information
            rep_path = self.disable_path.sub("", fs.get_additional_filename())
            fs.set_additional_filename(rep_path)
            ret_value["file_struct"] = fs

            return a_scan_callback_fn(ret_value)

    # ---------------------------------------------------------------------
    # __quarantine_file(self, filename)
    # Move the virus file to the quarantine folder
    # Argument: filename - Quarantine target file name
    # ---------------------------------------------------------------------
    def __quarantine_file(self, filename):
        if not self.options["infp_path"] or not self.options["opt_move"] and not self.options["opt_copy"]:
            return
        is_success = False

        with contextlib.suppress(shutil.Error, OSError):
            is_success = self.prepare_quarantine_path_and_move(filename)

        if isinstance(self.quarantine_callback_fn, types.FunctionType):
            if self.options["opt_copy"]:
                q_type = k2const.K2_QUARANTINE_COPY
            else:
                q_type = k2const.K2_QUARANTINE_MOVE

            self.quarantine_callback_fn(filename, is_success, q_type)

    def prepare_quarantine_path_and_move(self, filename):
        """
        Prepares quarantine path and moves/copies the infected file
        Returns True if successful, False otherwise
        """
        if self.options["opt_qname"]:
            if x := self.quarantine_name.get(filename, None):
                q_path = os.path.join(self.options["infp_path"], x)
                self.quarantine_name.pop(filename)
            else:
                q_path = self.options["infp_path"]
        else:
            q_path = self.options["infp_path"]

        if not os.path.exists(q_path):
            os.makedirs(q_path)  # Create multiple folders

        t_filename = (
            hashlib.sha256(open(filename, "rb").read()).hexdigest()
            if self.options["opt_qhash"]
            else os.path.split(filename)[-1]
        )
        # Check if the same file name exists in the quarantine folder
        fname = os.path.join(q_path, t_filename)
        t_quarantine_fname = fname
        count = 1
        while True:
            if os.path.exists(t_quarantine_fname):
                t_quarantine_fname = "%s (%d)" % (
                    fname,
                    count,
                )  # Create a unique file name
                count += 1
            else:
                break

        if self.options["opt_move"]:
            shutil.move(filename, t_quarantine_fname)  # Move to quarantine folder
        elif self.options["opt_copy"]:
            shutil.copy(filename, t_quarantine_fname)  # Copy to quarantine folder
            q_type = k2const.K2_QUARANTINE_COPY

        return True

    # ---------------------------------------------------------------------
    # __update_process(self, file_struct, immediately_flag=False)
    # Update update_info.
    # Argument: file_struct        - File information structure
    #           immediately_flag   - Whether to update all information in update_info
    # ---------------------------------------------------------------------
    def __update_process(self, file_struct, immediately_flag=False):
        # Do not immediately compress the compressed file information, check the internal structure and process it.
        if immediately_flag is False:
            if len(self.update_info) == 0:  # If no file is added
                self.update_info.append(file_struct)
            else:
                n_file_info = file_struct  # Current working file information
                p_file_info = self.update_info[-1]  # Previous file information

                # Is the master file the same? (Valid only when there is an archive engine)
                if (
                    p_file_info.get_master_filename() == n_file_info.get_master_filename()
                    and n_file_info.get_archive_engine_name() is not None
                ):
                    if p_file_info.get_level() > n_file_info.get_level():
                        ret_file_info = p_file_info
                        while ret_file_info.get_level() != n_file_info.get_level():
                            # If the master file is the same and the compression depth is different, update the internal file
                            ret_file_info = self.__update_arc_file_struct(ret_file_info)
                            self.update_info.append(ret_file_info)  # Add result file

                    # If the master file is the same and the compression depth continues to increase, continue to accumulate
                    self.update_info.append(n_file_info)
                elif len(self.update_info) == 1:  # If there is no cleanup point or target
                    self.__arcclose()
                    self.update_info = [file_struct]
                else:
                    immediately_flag = True

        # Use compressed file information to immediately compress and reassemble it into the final master file.
        if immediately_flag:
            # Close all handles for compressed files that need to be reassembled
            self.__arcclose()

            if len(self.update_info) > 1:  # If there is more than 1 file when reassembling
                ret_file_info = None

                while len(self.update_info):
                    p_file_info = self.update_info[-1]  # Previous file information
                    ret_file_info = self.__update_arc_file_struct(p_file_info)

                    if len(self.update_info):  # If it is not the top file, add the result
                        self.update_info.append(ret_file_info)

                self.update_info = [file_struct]

    # ---------------------------------------------------------------------
    # __update_arc_file_struct(self, p_file_info)
    # Process the compression in update_info.
    # Argument: p_file_info - The last file information structure in update_info
    # Return: Updated file information structure
    # ---------------------------------------------------------------------
    def __update_arc_file_struct(self, p_file_info):
        from kicomav.plugins import kernel

        # Extract all files with the same actual compressed file name
        t = []

        arc_level = p_file_info.get_level()
        arc_engine = p_file_info.get_archive_engine_name()
        if arc_engine:
            arc_engine = arc_engine.split(":")[0]

        while len(self.update_info):
            ename = self.update_info[-1].get_archive_engine_name()
            if ename:
                ename = ename.split(":")[0]

            if self.update_info[-1].get_level() == arc_level and ename == arc_engine:
                t.append(self.update_info.pop())
            else:
                break

        t.reverse()  # Change the order

        # File information to be returned (the top file of the compressed file)
        ret_file_info = self.update_info.pop()

        b_update = any(finfo.is_modify() for finfo in t)
        if b_update:  # If there is a modified file, proceed with re-compression
            self.repack_archive_file(t, kernel, ret_file_info)

        # Delete all compressed files (CWE-73 safe deletion)
        for tmp in t:
            t_fname = tmp.get_filename()
            # The file may have been treated (deleted) by the plugin engine
            if os.path.exists(t_fname):
                with contextlib.suppress(OSError, k2security.SecurityError):
                    t_fname_dir = os.path.dirname(t_fname)
                    k2security.safe_remove_file(t_fname, t_fname_dir)

        return ret_file_info

    def repack_archive_file(self, t, kernel, ret_file_info):
        """
        Repacks the archive file with modified contents
        Updates the status and triggers callbacks
        """
        arc_name = t[0].get_archive_filename()
        arc_engine_id = t[0].get_archive_engine_name()
        can_arc = t[-1].get_can_archive()

        # Proceed with re-compression
        # File compression (t) -> arc_name

        ret = False
        if can_arc == kernel.MASTER_PACK:  # Re-compression
            for inst in self.kavmain_inst:
                try:
                    ret = inst.mkarc(arc_engine_id, arc_name, t)
                    if ret:  # Final compression successful
                        break
                except AttributeError:
                    continue
        elif can_arc == kernel.MASTER_DELETE:  # Delete (CWE-73 safe deletion)
            with contextlib.suppress(k2security.SecurityError):
                arc_name_dir = os.path.dirname(arc_name)
                k2security.safe_remove_file(arc_name, arc_name_dir)
            ret = True

        if ret:
            ret_file_info.set_modify(True)  # Mark as modified
            if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                self.update_callback_fn(ret_file_info, True)
        else:
            ret_file_info.set_modify(False)  # Mark as not modified
            if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                self.update_callback_fn(ret_file_info, False)

    # ---------------------------------------------------------------------
    # __arcclose(self)
    # Close all opened compressed file handles.
    # ---------------------------------------------------------------------
    def __arcclose(self):
        for inst in self.kavmain_inst:
            with contextlib.suppress(AttributeError):
                inst.arcclose()

    # ---------------------------------------------------------------------
    # __disinfect_process(self, ret_value, action_type)
    # Treat the virus.
    # Argument: ret_value            - Virus scan result
    #          action_type            - Whether to treat or delete the virus
    # Return: Whether treatment is successful (True or False)
    # ---------------------------------------------------------------------
    def __disinfect_process(self, ret_value, action_type):
        if action_type == k2const.K2_ACTION_IGNORE:  # Ignore treatment
            return

        t_file_info = ret_value["file_struct"]  # Virus scan result
        mid = ret_value["virus_id"]
        eid = ret_value["engine_id"]

        d_fname = t_file_info.get_filename()
        d_ret = False

        if action_type == k2const.K2_ACTION_DISINFECT:  # Is the treatment option set?
            d_ret = self.disinfect(d_fname, mid, eid)
            if d_ret:
                self.result["Disinfected_files"] += 1  # Number of treated files
        elif action_type == k2const.K2_ACTION_DELETE:  # Is the delete option set? (CWE-73 safe deletion)
            try:
                d_fname_dir = os.path.dirname(d_fname)
                k2security.safe_remove_file(d_fname, d_fname_dir)
                d_ret = True
                self.result["Deleted_files"] += 1  # Number of deleted files
            except (IOError, OSError, k2security.SecurityError) as e:
                d_ret = False

        t_file_info.set_modify(d_ret)  # Mark as modified (treated/deleted)

        if isinstance(self.disinfect_callback_fn, types.FunctionType):
            self.disinfect_callback_fn(ret_value, action_type)

        return d_ret

    # ---------------------------------------------------------------------
    # __scan_file(self, file_struct, fileformat)
    # Request virus scan from plugin engine.
    # Argument: file_struct - File information structure of decompressed file
    #         format      - File format analysis information
    # Return: (Whether virus is found, virus name, virus ID, virus scan state, plugin engine ID)
    # ---------------------------------------------------------------------
    def __scan_file(self, file_struct, fileformat):
        from kicomav.plugins import kernel

        if self.verbose:
            print("[*] KavMain.__scan_file() :")

        fp = None
        mm = None

        try:
            ret = False
            vname = ""
            mid = -1
            scan_state = kernel.NOT_FOUND
            eid = -1

            filename = file_struct.get_filename()  # Extract the name of the file to be scanned
            filename_ex = file_struct.get_additional_filename()  # Name of the file inside the compressed file

            # If the file is not a file or the size is 0, there is no need to scan for viruses.
            if os.path.isfile(filename) is False:
                raise EngineKnownError("File is not found!")

            if os.path.getsize(filename) == 0:
                raise EngineKnownError("File Size is Zero!")

            fp = open(filename, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret, vname, mid, scan_state = inst.scan(mm, filename, fileformat, filename_ex)
                    if ret:  # If a virus is found
                        # Check if the malware name is in the whitelist
                        if self.__is_whitelisted(vname):
                            if self.verbose:
                                print(f"    [-] {inst.__module__}.__scan_file() : {vname} (whitelisted)")
                            ret = False  # Reset detection result
                            continue  # Continue to next engine

                        eid = i  # ID of the plugin engine that found the virus

                        if self.verbose:
                            print(f"    [-] {inst.__module__}.__scan_file() : {vname}")

                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()

            if fp:
                fp.close()

            return ret, vname, mid, scan_state, eid
        except (EngineKnownError, ValueError, OSError) as e:
            pass
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception:
            import traceback

            print(traceback.format_exc())

            self.result["IO_errors"] += 1  # Number of file I/O errors

        if mm:
            mm.close()

        if fp:
            fp.close()

        return False, "", -1, kernel.NOT_FOUND, -1

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id, engine_id)
    # Request virus treatment from plugin engine.
    # Argument: filename   - Name of the file to be treated
    #          malware_id - Infected malware ID
    #          engine_id  - ID of the plugin engine that found the virus
    # Return: Whether virus treatment is successful
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id, engine_id):
        ret = False

        if self.verbose:
            print("[*] KavMain.disinfect() :")

        with contextlib.suppress(AttributeError):
            # Request treatment only from the plugin engine that diagnosed the virus.
            inst = self.kavmain_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.verbose:
                print(f"    [-] {inst.__module__}.disinfect() : {ret}")

        return ret

    # ---------------------------------------------------------------------
    # unarc(self, file_struct)
    # Request decompression from plugin engine.
    # Argument: file_struct - File information structure of decompressed file
    # Return: (True, decompressed file information) or (False, error message)
    # ---------------------------------------------------------------------
    def unarc(self, file_struct):
        from kicomav.plugins import kernel

        rname_struct = None

        with contextlib.suppress(IOError):
            if file_struct.is_archive():  # Is it an archive?
                arc_engine_id = file_struct.get_archive_engine_name()  # Engine ID
                arc_name = file_struct.get_archive_filename()
                name_in_arc = file_struct.get_filename_in_archive()

                # Call the unarc member function of the archive engine module
                for inst in self.kavmain_inst:
                    try:
                        if unpack_data := inst.unarc(arc_engine_id, arc_name, name_in_arc):
                            # Decompress and create a temporary file
                            rname = self.temp_path.mktemp()
                            with open(rname, "wb") as fp:
                                fp.write(unpack_data)

                            # The master file processing method of the archive engine can be checked in getinfo
                            try:
                                can_arc = inst.getinfo()["make_arc_type"]
                            except (KeyError, AttributeError):
                                can_arc = kernel.MASTER_IGNORE

                            rname_struct = file_struct
                            rname_struct.set_filename(rname)
                            rname_struct.set_can_archive(can_arc)

                            # Is it a mode for creating a virus pattern?
                            if self.options["opt_sigtool"]:
                                # Create output folder in k2.py's directory
                                k2_dir = os.path.dirname(self.plugins_path)
                                output_dir = os.path.join(k2_dir, "output")
                                if not os.path.exists(output_dir):
                                    os.makedirs(output_dir)

                                # Copy the temporary file to the output folder
                                sig_fname = os.path.split(rname)[1]
                                shutil.copy(rname, os.path.join(output_dir, sig_fname))

                                # Create a sigtool.log file in output folder
                                t = rname_struct.get_additional_filename()
                                if t[0] in ["/", "\\"]:
                                    t = t[1:]
                                msg = f"{sig_fname} : {t}\n"

                                sigtool_log_path = os.path.join(output_dir, "sigtool.log")
                                with open(sigtool_log_path, "at") as fp:
                                    fp.write(msg)
                            break  # If decompression is successful, exit
                    except (AttributeError, struct.error) as e:
                        continue
                    except RuntimeError:  # Password protected zip file
                        return False, "password protected"
                    except MemoryError:
                        return False, None
                else:  # end for
                    rname_struct = self.handle_unsupported_archive(file_struct, kernel)
                return True, rname_struct
        return False, None

    def handle_unsupported_archive(self, file_struct, kernel):
        """
        Handles archives that cannot be decompressed by any engine
        Creates a temporary file and returns file info
        """
        # If no engine can decompress
        # Create a temporary file and exit
        rname = self.temp_path.mktemp()
        fp = open(rname, "wb")
        fp.close()

        result = file_struct
        result.set_filename(rname)
        result.set_can_archive(kernel.MASTER_IGNORE)
        return result

    # ---------------------------------------------------------------------
    # arclist(self, file_struct, fileformat)
    # Request the internal list of compressed files from the plugin engine.
    # Argument: file_struct - File information structure of decompressed file
    #         format      - File format analysis information
    # Return: [Internal list of compressed files] or []
    # ---------------------------------------------------------------------
    def arclist(self, file_struct, fileformat):
        from kicomav.plugins import kernel

        file_scan_list = []  # Contains all inspection information (k2file.FileStruct)

        rname = file_struct.get_filename()
        deep_name = file_struct.get_additional_filename()
        mname = file_struct.get_master_filename()
        level = file_struct.get_level()

        # Call the arclist member function of the archive engine module
        for inst in self.kavmain_inst:
            is_archive_engine = False
            can_arc = kernel.MASTER_IGNORE

            with contextlib.suppress(AttributeError):
                ret_getinfo = inst.getinfo()
                if "engine_type" in ret_getinfo and ret_getinfo["engine_type"] == kernel.ARCHIVE_ENGINE:
                    is_archive_engine = True

                if "make_arc_type" in ret_getinfo:
                    can_arc = ret_getinfo["make_arc_type"]

            with contextlib.suppress(AttributeError):
                arc_list = []  # Compressed file list

                if self.options["opt_arc"]:
                    # If the compression inspection option is set, call all
                    arc_list = inst.arclist(rname, fileformat, self.options.get("opt_password"))

                    # However, the count is processed only when it is an archive engine
                    if len(arc_list) and is_archive_engine:
                        self.result["Packed"] += 1
                elif not is_archive_engine:
                    arc_list = inst.arclist(rname, fileformat)
            if len(arc_list):  # If the compressed list exists, add and exit
                for alist in arc_list:
                    arc_id = alist[0]  # Always the archive engine ID
                    name = alist[1]  # Internal file name of the compressed file

                    if len(deep_name):  # For display inside the compressed file
                        try:
                            deep_name1 = deep_name
                            name1 = name

                            if type(deep_name) != type(name):
                                if isinstance(deep_name, str):
                                    name1 = name.encode("utf-8").decode("utf-8", "ignore")
                                elif isinstance(name, str):
                                    deep_name1 = deep_name.encode("utf-8").decode("utf-8", "ignore")

                            if name1.find("\\") != -1:
                                name1 = name1.replace("\\", "/")
                                name1 = name1[1:] if name1[0] == "/" else name1

                            dname = f"{deep_name1}/{name1}"
                        except UnicodeDecodeError:
                            continue
                    else:
                        dname = f"{name}"

                    fs = k2file.FileStruct()
                    fs.set_archive(arc_id, rname, name, dname, mname, False, can_arc, level + 1)
                    file_scan_list.append(fs)

                # break

        return file_scan_list

    # ---------------------------------------------------------------------
    # format(self, file_struct)
    # Request file format analysis from plugin engine.
    # Argument: file_struct - File information structure of decompressed file
    # Return: {File format analysis information} or {}
    # ---------------------------------------------------------------------
    def format(self, file_struct):
        ret = {}
        filename = file_struct.get_filename()
        filename_ex = file_struct.get_additional_filename()  # Internal file name of the compressed file

        fp = None
        mm = None

        with contextlib.suppress(IOError, EngineKnownError, ValueError, OSError):
            # If the file size is 0, there is no need to perform format analysis.
            if os.path.getsize(filename) == 0:
                raise EngineKnownError("File Size is Zero!")

            fp = open(filename, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            # Call the format member function of the engine module
            for inst in self.kavmain_inst:
                with contextlib.suppress(AttributeError):
                    if ff := inst.format(mm, filename, filename_ex):
                        ret |= ff

        if mm:
            mm.close()

        if fp:
            fp.close()

        return ret

    # ---------------------------------------------------------------------
    # getversion(self)
    # Passes the latest version information of all plugin engines.
    # Return: Latest version information
    # ---------------------------------------------------------------------
    def get_version(self):
        from kicomav.kavcore.updater import get_last_update_time

        return get_last_update_time()  # prefer update.cfg for update interval and fall back to __last_update__

    # ---------------------------------------------------------------------
    # set_options(self, options)
    # Set options.
    # ---------------------------------------------------------------------
    def set_options(self, options=None):
        if options:
            self.apply_custom_options(options)
        else:  # Set default values
            self.options["opt_arc"] = False
            self.options["opt_nor"] = False
            self.options["opt_list"] = False
            self.options["opt_move"] = False
            self.options["opt_copy"] = False
            self.options["opt_dis"] = False
            self.options["infp_path"] = None
            self.options["opt_verbose"] = False
            self.options["opt_sigtool"] = False
            self.options["opt_debug"] = False
            self.options["opt_qname"] = False
            self.options["opt_qhash"] = False
            self.options["opt_password"] = None
        return True

    def apply_custom_options(self, options):
        """
        Applies custom options provided by the user
        Sets all available options from the options object or dict
        """
        # Support both object attributes and dict access
        if isinstance(options, dict):
            self.options.update(options)
        else:
            self.options["opt_arc"] = options.opt_arc
            self.options["opt_nor"] = options.opt_nor
            self.options["opt_list"] = options.opt_list
            self.options["opt_move"] = options.opt_move
            self.options["opt_copy"] = options.opt_copy
            self.options["opt_dis"] = options.opt_dis
            self.options["infp_path"] = options.infp_path
            self.options["opt_verbose"] = options.opt_verbose
            self.options["opt_sigtool"] = options.opt_sigtool
            self.options["opt_debug"] = options.opt_debug
            self.options["opt_qname"] = options.opt_qname
            self.options["opt_qhash"] = options.opt_qhash
            self.options["opt_password"] = getattr(options, "opt_password", None)

    # -----------------------------------------------------------------
    # set_result(self)
    # Initialize the virus detection result of the antivirus engine.
    # -----------------------------------------------------------------
    def set_result(self):
        self.result["Folders"] = 0  # Folder count
        self.result["Files"] = 0  # File count
        self.result["Packed"] = 0  # Compressed file count
        self.result["Infected_files"] = 0  # Total number of detected viruses (infected)
        self.result["Suspect_files"] = 0  # Total number of detected viruses (suspicious)
        self.result["Warnings"] = 0  # Total number of detected viruses (warning)
        self.result["Identified_viruses"] = 0  # Total number of unique viruses detected
        self.result["Disinfected_files"] = 0  # File count treated
        self.result["Deleted_files"] = 0  # File count deleted
        self.result["IO_errors"] = 0  # File I/O error count

    # -----------------------------------------------------------------
    # reset_result(self)
    # Reset result counters for worker pool reuse
    # -----------------------------------------------------------------
    def reset_result(self):
        self.set_result()
        self.identified_virus = set()  # Clear identified viruses

    # -----------------------------------------------------------------
    # get_result(self)
    # Get the virus detection result of the antivirus engine.
    # Return: Virus detection result
    # -----------------------------------------------------------------
    def get_result(self):
        # Count the number of unique viruses found so far.
        self.result["Identified_viruses"] = len(self.identified_virus)
        return self.result

    # -----------------------------------------------------------------
    # get_signum(self)
    # Get the number of viruses that the antivirus engine can diagnose/treat.
    # Return: Number of viruses that can be diagnosed/treated
    # -----------------------------------------------------------------
    def get_signum(self):
        signum = 0  # Number of viruses that can be diagnosed/treated

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()

                # Accumulate the number of viruses that can be diagnosed/treated in the plugin engine information
                if "sig_num" in ret:
                    signum += ret["sig_num"]
            except AttributeError:
                continue

        return signum
