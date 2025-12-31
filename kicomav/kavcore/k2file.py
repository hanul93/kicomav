# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import contextlib
import os
import re
import glob
import shutil
import tempfile


# ---------------------------------------------------------------------
# K2Tempfile Class
# ---------------------------------------------------------------------
class K2Tempfile:
    def __init__(self):
        self.re_pid = re.compile(r"ktmp([0-9a-f]{5})$", re.IGNORECASE)

        self.temp_path = os.path.join(tempfile.gettempdir(), f"ktmp{os.getpid():05x}")

        if not os.path.exists(self.temp_path):
            try:
                os.mkdir(self.temp_path)
            except (IOError, OSError) as e:
                self.temp_path = tempfile.gettempdir()

    def gettempdir(self):
        return self.temp_path

    def mktemp(self):
        """
        Create a secure temporary file and return its path.
        Uses mkstemp instead of mktemp to prevent race condition (CWE-377).
        """
        fd, path = tempfile.mkstemp(prefix="ktmp", dir=self.temp_path)
        os.close(fd)  # Close file descriptor, file remains
        return path

    def removetempdir(self):
        # Delete only the self folder
        with contextlib.suppress(OSError):
            if os.path.exists(self.temp_path):
                shutil.rmtree(self.temp_path)


# -------------------------------------------------------------------------
# FileStruct Class
# -------------------------------------------------------------------------
class FileStruct:
    # ---------------------------------------------------------------------
    # __init__(self, filename=None)
    # Initialize the class
    # Argument: filename - File name
    # ---------------------------------------------------------------------
    def __init__(self, filename=None, level=0):
        self.__fs = {}

        if filename:
            self.set_default(filename, level)

    # ---------------------------------------------------------------------
    # set_default(self, filename)
    # Create a FileStruct for a file
    # Argument: filename - File name
    # ---------------------------------------------------------------------
    def set_default(self, filename, level):
        from kicomav.plugins import kernel

        self.__fs["is_arc"] = False  # Compression status
        self.__fs["arc_engine_name"] = None  # Decompression engine ID
        self.__fs["arc_filename"] = ""  # Actual compressed file
        self.__fs["filename_in_arc"] = ""  # Decompression target file
        self.__fs["real_filename"] = filename  # Inspection target file
        self.__fs["additional_filename"] = ""  # File name for internal representation of compressed file
        self.__fs["master_filename"] = filename  # Output
        self.__fs["is_modify"] = False  # Modify status
        self.__fs["can_arc"] = kernel.MASTER_IGNORE  # Recompression possible status
        self.__fs["level"] = level  # Compression depth

    # ---------------------------------------------------------------------
    # is_archive(self)
    # Check the compression status of the file
    # Return: True or False
    # ---------------------------------------------------------------------
    def is_archive(self):  # Compression status
        return self.__fs["is_arc"]

    # ---------------------------------------------------------------------
    # get_archive_engine_name(self)
    # Check the decompression engine
    # Return: Decompression engine (ex, arc_zip)
    # ---------------------------------------------------------------------
    def get_archive_engine_name(self):  # Compression engine ID
        return self.__fs["arc_engine_name"]

    # ---------------------------------------------------------------------
    # get_archive_filename(self)
    # Check the actual compressed file name
    # Return: Actual compressed file name
    # ---------------------------------------------------------------------
    def get_archive_filename(self):  # Actual compressed file
        return self.__fs["arc_filename"]

    # ---------------------------------------------------------------------
    # get_filename_in_archive(self)
    # Check the decompression target file name
    # Return: Decompression target file
    # ---------------------------------------------------------------------
    def get_filename_in_archive(self):  # Decompression target file
        return self.__fs["filename_in_arc"]

    # ---------------------------------------------------------------------
    # get_filename(self)
    # Check the actual working target file name
    # Return: Actual working target file
    # ---------------------------------------------------------------------
    def get_filename(self):  # Actual working file name
        return self.__fs["real_filename"]

    # ---------------------------------------------------------------------
    # set_filename(self)
    # Save the actual working target file name
    # Argument: Actual working target file
    # ---------------------------------------------------------------------
    def set_filename(self, fname):  # Actual working file name
        self.__fs["real_filename"] = fname

    # ---------------------------------------------------------------------
    # get_master_filename(self)
    # Check the top file name
    # Return: Compressed file name
    # ---------------------------------------------------------------------
    def get_master_filename(self):  # Top file name
        return self.__fs["master_filename"]  # Output

    # ---------------------------------------------------------------------
    # get_additional_filename(self)
    # Check the file name for representing the compressed file
    # Return: File name for representing the compressed file
    # ---------------------------------------------------------------------
    def get_additional_filename(self):
        return self.__fs["additional_filename"]

    # ---------------------------------------------------------------------
    # set_additional_filename(self, filename)
    # Set the file name for representing the compressed file
    # ---------------------------------------------------------------------
    def set_additional_filename(self, filename):
        self.__fs["additional_filename"] = filename

    # ---------------------------------------------------------------------
    # is_modify(self)
    # Check if the file has been modified due to virus removal
    # Return: True or False
    # ---------------------------------------------------------------------
    def is_modify(self):  # Modify status
        return self.__fs["is_modify"]

    # ---------------------------------------------------------------------
    # set_modify(self, modify)
    # Save the modification status due to virus removal
    # Argument: Modify status (True or False)
    # ---------------------------------------------------------------------
    def set_modify(self, modify):  # Modify status
        self.__fs["is_modify"] = modify

    # ---------------------------------------------------------------------
    # get_can_archive(self)
    # Check if the file can be recompressed after virus removal
    # Return: kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def get_can_archive(self):  # Recompression possible status
        return self.__fs["can_arc"]

    # ---------------------------------------------------------------------
    # set_can_archive(self, mode)
    # Set if the file can be recompressed after virus removal
    # Argument: mode - kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def set_can_archive(self, mode):  # Recompression possible status
        self.__fs["can_arc"] = mode

    # ---------------------------------------------------------------------
    # get_level(self)
    # Check the compression depth
    # Return: 0, 1, 2 ...
    # ---------------------------------------------------------------------
    def get_level(self):  # Compression depth
        return self.__fs["level"]

    # ---------------------------------------------------------------------
    # set_level(self, level)
    # Set the compression depth
    # Argument: level - Compression depth
    # ---------------------------------------------------------------------
    def set_level(self, level):  # Compression depth
        self.__fs["level"] = level

    # ---------------------------------------------------------------------
    # set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc)
    # Save the file information given the information
    # Argument: engine_id - Decompression possible engine ID
    #           rname     - Compressed file
    #           fname     - Decompression target file
    #           dname     - File name for representing the compressed file
    #           mname     - Master file (Top file name)
    #           modify    - Modify status
    #           can_arc   - Recompression possible status
    #           level     - Compression depth
    # ---------------------------------------------------------------------
    def set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc, level):
        self.__fs["is_arc"] = True  # Compression status
        self.__fs["arc_engine_name"] = engine_id  # Decompression possible engine ID
        self.__fs["arc_filename"] = rname  # Actual compressed file
        self.__fs["filename_in_arc"] = fname  # Decompression target file
        self.__fs["real_filename"] = ""  # Inspection target file
        self.__fs["additional_filename"] = dname  # File name for representing the compressed file
        self.__fs["master_filename"] = mname  # Master file (Top file name)
        self.__fs["is_modify"] = modify  # Modify status
        self.__fs["can_arc"] = can_arc  # Recompression possible status
        self.__fs["level"] = level  # Compression depth
