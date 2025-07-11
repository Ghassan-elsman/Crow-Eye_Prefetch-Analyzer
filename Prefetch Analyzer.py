import os
import struct
import datetime
import enum
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional
import re
import json
import csv
import logging
from multiprocessing import Pool
from tqdm import tqdm


# ASCII Art Logo
LOGO = """
═══════════════════════════════════════════════════════════════════
 ██████╗██████╗  ██████╗ ██╗    ██╗      ███████╗██╗   ██╗███████╗
██╔════╝██╔══██╗██╔═══██╗██║    ██║      ██╔════╝╚██╗ ██╔╝██╔════╝
██║     ██████╔╝██║   ██║██║ █╗ ██║█████╗█████╗   ╚████╔╝ █████╗  
██║     ██╔══██╗██║   ██║██║███╗██║╚════╝██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝      ███████╗   ██║   ███████╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝       ╚══════╝   ╚═╝   ╚══════╝
                    [ CROW-EYE PREFETCH ANALYZER ]
═══════════════════════════════════════════════════════════════════
"""

# Define default paths
PREFETCH_DIR = "C:\\Windows\\Prefetch"
DB_PATH = "prefetch_data3.db"
JSON_PATH = "prefetch_data.json"
CSV_PATH = "prefetch_data.csv"
LOG_FILE = "prefetch_analyzer.log"

# Setup logging
logging.basicConfig(
    level=logging.WARNING,
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_and_install_packages():
    required_packages = ['sqlite3', 'tqdm','ctypes']
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} not found. Attempting to install...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"Successfully installed {package}")
            except subprocess.CalledProcessError:
                print(f"Failed to install {package}. Please install it manually using 'pip install {package}'")
                sys.exit(1)

# Check and install required packages
check_and_install_packages()

# Now import the packages
import sqlite3
import ctypes
from ctypes import windll, wintypes

class Version(enum.IntEnum):
    WIN_XP_OR_2003 = 17
    VISTA_OR_WIN7 = 23
    WIN8X_OR_WIN2012X = 26
    WIN10_OR_WIN11 = 30
    WIN11 = 31

@dataclass
class Header:
    version: Version
    signature: str
    file_size: int
    executable_filename: str
    hash: str

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Header':
        version = Version(struct.unpack_from("<I", data, 0)[0])
        signature = data[4:8].decode('ascii')
        file_size = struct.unpack_from("<I", data, 12)[0]
        
        exe_filename_bytes = data[16:76]
        exe_filename = exe_filename_bytes.decode('utf-16le').split('\x00')[0].strip()
        
        hash_val = hex(struct.unpack_from("<I", data, 76)[0])[2:].upper()
        
        return cls(version, signature, file_size, exe_filename, hash_val)

@dataclass
class MFTInformation:
    mft_entry: int
    sequence_number: int
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MFTInformation':
        entry_seq = struct.unpack("<Q", data)[0]
        mft_entry = entry_seq & 0xFFFFFFFFFFFF
        sequence_number = entry_seq >> 48
        
        return cls(mft_entry, sequence_number)
    
    def __str__(self) -> str:
        return f"{self.mft_entry}-{self.sequence_number}"

@dataclass
class FileMetric:
    unknown0: int = 0
    unknown1: int = 0
    unknown2: int = 0
    unknown3: int = 0
    filename_string_offset: int = 0
    filename_string_size: int = 0
    mft_info: Optional[MFTInformation] = None
    
    @classmethod
    def from_bytes(cls, data: bytes, is_version17: bool) -> 'FileMetric':
        if is_version17:
            unknown0 = struct.unpack_from("<I", data, 0)[0]
            unknown1 = struct.unpack_from("<I", data, 4)[0]
            filename_offset = struct.unpack_from("<I", data, 8)[0]
            filename_size = struct.unpack_from("<I", data, 12)[0]
            unknown2 = struct.unpack_from("<I", data, 16)[0]
            
            return cls(
                unknown0=unknown0,
                unknown1=unknown1,
                filename_string_offset=filename_offset,
                filename_string_size=filename_size,
                unknown2=unknown2
            )
        else:
            unknown0 = struct.unpack_from("<I", data, 0)[0]
            unknown1 = struct.unpack_from("<I", data, 4)[0]
            unknown2 = struct.unpack_from("<I", data, 8)[0]
            filename_offset = struct.unpack_from("<I", data, 12)[0]
            filename_size = struct.unpack_from("<I", data, 16)[0]
            unknown3 = struct.unpack_from("<I", data, 20)[0]
            
            mft_info = MFTInformation.from_bytes(data[24:32])
            
            return cls(
                unknown0=unknown0,
                unknown1=unknown1,
                unknown2=unknown2,
                unknown3=unknown3,
                filename_string_offset=filename_offset,
                filename_string_size=filename_size,
                mft_info=mft_info
            )

@dataclass
class TraceChain:
    next_array_entry_index: int
    total_block_load_count: int
    unknown0: int = 0
    loaded_block_count: int = 0
    
    @classmethod
    def from_bytes(cls, data: bytes, has_loaded_count: bool) -> 'TraceChain':
        next_index = struct.unpack_from("<I", data, 0)[0]
        total_count = struct.unpack_from("<I", data, 4)[0]
        
        if has_loaded_count:
            unknown = struct.unpack_from("<H", data, 8)[0]
            loaded_count = struct.unpack_from("<H", data, 10)[0]
            return cls(next_index, total_count, unknown, loaded_count)
        else:
            unknown = struct.unpack_from("<I", data, 8)[0]
            return cls(next_index, total_count, unknown)

@dataclass
class VolumeInfo:
    device_name_offset: int
    creation_time: datetime.datetime
    serial_number: str
    device_name: str
    file_references: List[MFTInformation] = field(default_factory=list)
    directory_names: List[str] = field(default_factory=list)

class PrefetchFile:
    SIGNATURE = 0x41434353  # 'SCCA' in little-endian
    
    def __init__(self):
        self.raw_bytes = None
        self.source_filename = ""
        self.source_created_on = None
        self.source_modified_on = None
        self.source_accessed_on = None
        
        self.header = None
        self.file_metrics_offset = 0
        self.file_metrics_count = 0
        self.filename_strings_offset = 0
        self.filename_strings_size = 0
        self.volumes_info_offset = 0
        self.volume_count = 0
        self.volumes_info_size = 0
        self.total_directory_count = -1
        
        self.last_run_times = []
        self.volume_information = []
        self.run_count = 0
        self.parsing_error = False
        
        self.filenames = []
        self.file_metrics = []

    @classmethod
    def open(cls, file_path: str) -> 'PrefetchFile':
        # Validate file size before parsing
        if os.path.getsize(file_path) < 84:
            logging.warning(f"File {file_path} is too small to be a valid prefetch file")
            raise ValueError(f"File {file_path} is too small to be a valid prefetch file")
        
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()
            return cls.from_bytes(raw_bytes, file_path)
    
    @staticmethod
    def _decompress_win10_prefetch(data: bytes) -> bytes:
        if data[:3] == b'MAM':
            try:
                size = struct.unpack("<I", data[4:8])[0]
                compressed_data = data[8:]
                
                if os.name == 'nt':
                    COMPRESSION_FORMAT_XPRESS_HUFF = 4
                    ntdll = windll.ntdll
                    
                    compress_workspace_size = wintypes.ULONG()
                    compress_fragment_workspace_size = wintypes.ULONG()
                    
                    status = ntdll.RtlGetCompressionWorkSpaceSize(
                        COMPRESSION_FORMAT_XPRESS_HUFF,
                        ctypes.byref(compress_workspace_size),
                        ctypes.byref(compress_fragment_workspace_size)
                    )
                    
                    if status != 0:
                        raise Exception(f"RtlGetCompressionWorkSpaceSize failed with status {status}")
                    
                    workspace = (ctypes.c_ubyte * compress_fragment_workspace_size.value)()
                    uncompressed_buffer = (ctypes.c_ubyte * size)()
                    final_size = wintypes.ULONG()
                    
                    compressed_buffer = (ctypes.c_ubyte * len(compressed_data))()
                    for i, b in enumerate(compressed_data):
                        compressed_buffer[i] = b
                    
                    status = ntdll.RtlDecompressBufferEx(
                        COMPRESSION_FORMAT_XPRESS_HUFF,
                        uncompressed_buffer,
                        size,
                        compressed_buffer,
                        len(compressed_data),
                        ctypes.byref(final_size),
                        workspace
                    )
                    
                    if status != 0:
                        raise Exception(f"RtlDecompressBufferEx failed with status {status}")
                    
                    return bytes(uncompressed_buffer)
                else:
                    raise NotImplementedError(
                        "Windows 10/11 prefetch decompression is only supported on Windows."
                    )
            except Exception as e:
                logging.error(f"Error decompressing Windows 10/11 prefetch: {e}")
                raise
        return data

    @classmethod
    def from_bytes(cls, data: bytes, source_filename: str = "") -> 'PrefetchFile':
        data = cls._decompress_win10_prefetch(data)
        
        signature = struct.unpack_from("<I", data, 4)[0]
        if signature != cls.SIGNATURE:
            logging.warning(f"Invalid signature in {source_filename}: {signature:08X}")
            raise ValueError(f"Invalid signature: {signature:08X}, expected 'SCCA' (0x{cls.SIGNATURE:08X})")
        
        version = struct.unpack_from("<I", data, 0)[0]
        
        instance = cls()
        instance.raw_bytes = data
        instance.source_filename = source_filename
        
        if source_filename:
            try:
                stat_info = os.stat(source_filename)
                instance.source_created_on = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                instance.source_modified_on = datetime.datetime.fromtimestamp(stat_info.st_mtime)
                instance.source_accessed_on = datetime.datetime.fromtimestamp(stat_info.st_atime)
            except Exception as e:
                logging.warning(f"Error getting file stats for {source_filename}: {e}")
        
        try:
            if version == Version.WIN_XP_OR_2003:
                instance._parse_version17()
            elif version == Version.VISTA_OR_WIN7:
                instance._parse_version23()
            elif version == Version.WIN8X_OR_WIN2012X:
                instance._parse_version26()
            elif version == Version.WIN10_OR_WIN11 or version == Version.WIN11:
                instance._parse_version30or31()
            else:
                logging.warning(f"Unknown version in {source_filename}: {version}")
                raise ValueError(f"Unknown version: {version}")
            
            if instance.run_count > 1000000:
                logging.warning(f"High run count ({instance.run_count}) in {source_filename}, potential parsing error")
        except Exception as e:
            logging.error(f"Error parsing prefetch file {source_filename}: {e}")
            instance.parsing_error = True
            
        return instance
    
    def _parse_version17(self):
        header_bytes = self.raw_bytes[:84]
        self.header = Header.from_bytes(header_bytes)
        
        file_info_bytes = self.raw_bytes[84:152]
        
        self.file_metrics_offset = struct.unpack_from("<I", file_info_bytes, 0)[0]
        self.file_metrics_count = struct.unpack_from("<I", file_info_bytes, 4)[0]
        
        self.filename_strings_offset = struct.unpack_from("<I", file_info_bytes, 16)[0]
        self.filename_strings_size = struct.unpack_from("<I", file_info_bytes, 20)[0]
        
        self.volumes_info_offset = struct.unpack_from("<I", file_info_bytes, 24)[0]
        self.volume_count = struct.unpack_from("<I", file_info_bytes, 28)[0]
        
        self.volumes_info_size = struct.unpack_from("<I", file_info_bytes, 32)[0]
        
        raw_time = struct.unpack_from("<Q", file_info_bytes, 36)[0]
        self.last_run_times = [self._filetime_to_datetime(raw_time)]
        
        self.run_count = struct.unpack_from("<I", file_info_bytes, 60)[0]
        
        self._parse_file_metrics(True)
        self._parse_filenames()
        self._parse_volume_info()
    
    def _parse_version23(self):
        header_bytes = self.raw_bytes[:84]
        self.header = Header.from_bytes(header_bytes)
        
        file_info_bytes = self.raw_bytes[84:156]
        
        self.file_metrics_offset = struct.unpack_from("<I", file_info_bytes, 0)[0]
        self.file_metrics_count = struct.unpack_from("<I", file_info_bytes, 4)[0]
        
        self.filename_strings_offset = struct.unpack_from("<I", file_info_bytes, 16)[0]
        self.filename_strings_size = struct.unpack_from("<I", file_info_bytes, 20)[0]
        
        self.volumes_info_offset = struct.unpack_from("<I", file_info_bytes, 24)[0]
        self.volume_count = struct.unpack_from("<I", file_info_bytes, 28)[0]
        
        self.volumes_info_size = struct.unpack_from("<I", file_info_bytes, 32)[0]
        
        run_time_offset = 44
        self.last_run_times = []
        for i in range(8):
            raw_time = struct.unpack_from("<Q", file_info_bytes, run_time_offset)[0]
            if raw_time > 0:
                self.last_run_times.append(self._filetime_to_datetime(raw_time))
            run_time_offset += 8
        
        self.run_count = struct.unpack_from("<I", file_info_bytes, run_time_offset)[0]
        
        self._parse_file_metrics(False)
        self._parse_filenames()
        self._parse_volume_info()
    
    def _parse_version26(self):
        header_bytes = self.raw_bytes[:84]
        self.header = Header.from_bytes(header_bytes)
        
        file_info_bytes = self.raw_bytes[84:224]
        
        self.file_metrics_offset = struct.unpack_from("<I", file_info_bytes, 0)[0]
        self.file_metrics_count = struct.unpack_from("<I", file_info_bytes, 4)[0]
        
        self.filename_strings_offset = struct.unpack_from("<I", file_info_bytes, 16)[0]
        self.filename_strings_size = struct.unpack_from("<I", file_info_bytes, 20)[0]
        
        self.volumes_info_offset = struct.unpack_from("<I", file_info_bytes, 24)[0]
        self.volume_count = struct.unpack_from("<I", file_info_bytes, 28)[0]
        
        self.volumes_info_size = struct.unpack_from("<I", file_info_bytes, 32)[0]
        
        self.total_directory_count = struct.unpack_from("<I", file_info_bytes, 36)[0]
        
        run_time_offset = 44
        self.last_run_times = []
        for i in range(8):
            raw_time = struct.unpack_from("<Q", file_info_bytes, run_time_offset)[0]
            if raw_time > 0:
                self.last_run_times.append(self._filetime_to_datetime(raw_time))
            run_time_offset += 8
        
        self.run_count = struct.unpack_from("<I", file_info_bytes, run_time_offset)[0]
        
        self._parse_file_metrics(False)
        self._parse_filenames()
        self._parse_volume_info()
    
    def _parse_version30or31(self):
        header_bytes = self.raw_bytes[:84]
        self.header = Header.from_bytes(header_bytes)
        
        file_info_bytes = self.raw_bytes[84:224]
        
        self.file_metrics_offset = struct.unpack_from("<I", file_info_bytes, 0)[0]
        self.file_metrics_count = struct.unpack_from("<I", file_info_bytes, 4)[0]
        
        self.filename_strings_offset = struct.unpack_from("<I", file_info_bytes, 16)[0]
        self.filename_strings_size = struct.unpack_from("<I", file_info_bytes, 20)[0]
        
        self.volumes_info_offset = struct.unpack_from("<I", file_info_bytes, 24)[0]
        self.volume_count = struct.unpack_from("<I", file_info_bytes, 28)[0]
        
        self.volumes_info_size = struct.unpack_from("<I", file_info_bytes, 32)[0]
        
        self.total_directory_count = struct.unpack_from("<I", file_info_bytes, 36)[0]
        
        run_time_offset = 44
        self.last_run_times = []
        for i in range(8):
            raw_time = struct.unpack_from("<Q", file_info_bytes, run_time_offset)[0]
            if raw_time > 0:
                self.last_run_times.append(self._filetime_to_datetime(raw_time))
            run_time_offset += 8
        
        self.run_count = struct.unpack_from("<I", file_info_bytes, run_time_offset)[0]
        
        self._parse_file_metrics(False)
        self._parse_filenames()
        self._parse_volume_info()
    
    def _parse_file_metrics(self, is_version17: bool):
        self.file_metrics = []
        
        if self.file_metrics_count == 0:
            return
        
        metric_size = 20 if is_version17 else 32
        
        metrics_end = self.file_metrics_offset + (self.file_metrics_count * metric_size)
        if metrics_end > len(self.raw_bytes):
            logging.warning(f"File metrics extend beyond file size in {self.source_filename}")
            return
        
        try:
            metrics_data = self.raw_bytes[self.file_metrics_offset:metrics_end]
            
            for i in range(self.file_metrics_count):
                offset = i * metric_size
                if offset + metric_size > len(metrics_data):
                    logging.warning(f"Incomplete file metric at index {i} in {self.source_filename}")
                    break
                
                metric_data = metrics_data[offset:offset + metric_size]
                self.file_metrics.append(FileMetric.from_bytes(metric_data, is_version17))
        except Exception as e:
            logging.error(f"Error parsing file metrics in {self.source_filename}: {e}")
    
    def _parse_filenames(self):
        self.filenames = []
        
        if self.filename_strings_size == 0:
            return
        
        if self.filename_strings_offset + self.filename_strings_size > len(self.raw_bytes):
            logging.warning(f"Filename strings extend beyond file size in {self.source_filename}")
            return
        
        try:
            filenames_data = self.raw_bytes[self.filename_strings_offset:
                                            self.filename_strings_offset + self.filename_strings_size]
            
            filenames_str = filenames_data.decode('utf-16le')
            self.filenames = [name for name in filenames_str.split('\x00') if name]
        except Exception as e:
            logging.error(f"Error parsing filename strings in {self.source_filename}: {e}")
    
    def _parse_volume_info(self):
        self.volume_information = []
        
        if self.volumes_info_size == 0 or self.volume_count == 0:
            logging.warning(f"No volume information in prefetch file {self.source_filename}")
            return
        
        if self.volumes_info_offset + self.volumes_info_size > len(self.raw_bytes):
            logging.warning(f"Volume info extends beyond file size in {self.source_filename}")
            return
        
        vol_entry_size = 40
        
        try:
            volume_data = self.raw_bytes[self.volumes_info_offset:
                                        self.volumes_info_offset + self.volumes_info_size]
            
            for i in range(self.volume_count):
                if i * vol_entry_size + vol_entry_size > len(volume_data):
                    logging.warning(f"Not enough data for volume {i+1}/{self.volume_count} in {self.source_filename}")
                    break
                
                offset = i * vol_entry_size
                vol_data = volume_data[offset:offset + vol_entry_size]
                
                try:
                    vol_dev_offset = struct.unpack_from("<I", vol_data, 0)[0]
                    vol_dev_num_char = struct.unpack_from("<I", vol_data, 4)[0]
                    
                    creation_time_raw = struct.unpack_from("<Q", vol_data, 8)[0]
                    creation_time = self._filetime_to_datetime(creation_time_raw)
                    
                    serial_number = hex(struct.unpack_from("<I", vol_data, 16)[0])[2:].upper()
                    
                    if self.volumes_info_offset + vol_dev_offset + (vol_dev_num_char * 2) > len(self.raw_bytes):
                        logging.warning(f"Device name for volume {i+1} extends beyond file size in {self.source_filename}")
                        device_name = "Unknown Device"
                    else:
                        try:
                            dev_name_bytes = self.raw_bytes[self.volumes_info_offset + vol_dev_offset:
                                                        self.volumes_info_offset + vol_dev_offset + (vol_dev_num_char * 2)]
                            device_name = dev_name_bytes.decode('utf-16le')
                            
                            readable_name = self._get_readable_volume_name(device_name, serial_number)
                            if readable_name:
                                device_name = f"{device_name} ({readable_name})"
                        except Exception as e:
                            logging.warning(f"Error decoding device name in {self.source_filename}: {e}")
                            device_name = f"Device-{serial_number}"
                    
                    vol_info = VolumeInfo(vol_dev_offset, creation_time, serial_number, device_name)
                    
                    file_ref_offset = struct.unpack_from("<I", vol_data, 20)[0]
                    file_ref_size = struct.unpack_from("<I", vol_data, 24)[0]
                    
                    dir_strings_offset = struct.unpack_from("<I", vol_data, 28)[0]
                    num_dir_strings = struct.unpack_from("<I", vol_data, 32)[0]
                    
                    if self.volumes_info_offset + file_ref_offset + file_ref_size > len(self.raw_bytes):
                        logging.warning(f"File references for volume {i+1} extend beyond file size in {self.source_filename}")
                    else:
                        try:
                            file_refs_index = self.volumes_info_offset + file_ref_offset
                            file_ref_bytes = self.raw_bytes[file_refs_index:file_refs_index + file_ref_size]
                            
                            if len(file_ref_bytes) >= 8:
                                file_ref_ver = struct.unpack_from("<I", file_ref_bytes, 0)[0]
                                num_file_refs = struct.unpack_from("<I", file_ref_bytes, 4)[0]
                                
                                temp_index = 8
                                while temp_index + 8 <= len(file_ref_bytes) and len(vol_info.file_references) < num_file_refs:
                                    mft_data = file_ref_bytes[temp_index:temp_index + 8]
                                    vol_info.file_references.append(MFTInformation.from_bytes(mft_data))
                                    temp_index += 8
                        except Exception as e:
                            logging.warning(f"Error parsing file references in {self.source_filename}: {e}")
                    
                    if self.volumes_info_offset + dir_strings_offset > len(self.raw_bytes):
                        logging.warning(f"Directory strings for volume {i+1} extend beyond file size in {self.source_filename}")
                    else:
                        try:
                            dir_strings_index = self.volumes_info_offset + dir_strings_offset
                            dir_strings_bytes = self.raw_bytes[dir_strings_index:]
                            
                            temp_index = 0
                            for k in range(num_dir_strings):
                                if temp_index + 2 > len(dir_strings_bytes):
                                    break
                                
                                dir_char_count = struct.unpack_from("<H", dir_strings_bytes, temp_index)[0] * 2 + 2
                                temp_index += 2
                                
                                if temp_index + dir_char_count > len(dir_strings_bytes):
                                    break
                                
                                dir_name_bytes = dir_strings_bytes[temp_index:temp_index + dir_char_count]
                                dir_name = dir_name_bytes.decode('utf-16le').rstrip('\x00')
                                vol_info.directory_names.append(dir_name)
                                
                                temp_index += dir_char_count
                        except Exception as e:
                            logging.warning(f"Error parsing directory strings in {self.source_filename}: {e}")
                    
                    self.volume_information.append(vol_info)
                except Exception as e:
                    logging.error(f"Error parsing volume {i+1} in {self.source_filename}: {e}")
        except Exception as e:
            logging.error(f"Error parsing volume information in {self.source_filename}: {e}")
    
    @staticmethod
    def _filetime_to_datetime(filetime: int) -> datetime.datetime:
        if filetime == 0:
            return None
        
        seconds_since_1601 = filetime / 10000000
        epoch_diff = 11644473600
        timestamp = seconds_since_1601 - epoch_diff
        
        return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    
    def _format_paths_with_drive_letters(self, paths):
        formatted_paths = []
        
        for path in paths:
            drive_letter = None
            volume_id = None
            
            if "\\VOLUME{" in path:
                for vol in self.volume_information:
                    if vol.device_name in path:
                        if "Drive" in vol.device_name and ":" in vol.device_name:
                            match = re.search(r'Drive ([A-Z]):', vol.device_name)
                            if match:
                                drive_letter = match.group(1)
                                volume_id = vol.device_name
                                break
            
            if drive_letter and volume_id:
                idx = path.find(volume_id)
                if idx >= 0:
                    end_idx = idx + len(volume_id)
                    rest_of_path = path[end_idx:].lstrip("\\")
                    formatted_path = f"{drive_letter}:\\{rest_of_path}"
                    formatted_paths.append(formatted_path)
                    continue
        
            formatted_paths.append(path)
        
        return formatted_paths

    def get_data_dict(self):
        filename = os.path.basename(self.source_filename) if self.source_filename else "Unknown"
        most_recent = max([t for t in self.last_run_times if t is not None], default=None)

        drive_letters = {}
        volume_pattern = re.compile(r'\\VOLUME\{[0-9a-f-]+\}', re.IGNORECASE)
        
        for vol in self.volume_information:
            if "Drive" in vol.device_name and ":" in vol.device_name:
                match = re.search(r'Drive ([A-Z]):', vol.device_name)
                if match:
                    drive_letter = match.group(1)
                    drive_letters[vol.device_name] = drive_letter
                    volume_match = volume_pattern.search(vol.device_name)
                    if volume_match:
                        volume_id = volume_match.group(0)
                        drive_letters[volume_id] = drive_letter

        volumes_data = []
        directories_data = []
        for i, vol in enumerate(self.volume_information, 1):
            drive_letter = drive_letters.get(vol.device_name)
            vol_id = f"{drive_letter}:" if drive_letter else f"Volume{i}"
            volumes_data.append({
                "volume_id": vol_id,
                "device_name": vol.device_name,
                "creation_time": str(vol.creation_time) if vol.creation_time else None,
                "serial_number": vol.serial_number
            })
            
            formatted_dirs = []
            for dir_name in vol.directory_names:
                formatted_dir = dir_name
                volume_match = volume_pattern.search(dir_name)
                if volume_match and drive_letter:
                    volume_id = volume_match.group(0)
                    rest_of_path = dir_name[volume_match.end():].lstrip("\\")
                    formatted_dir = f"{drive_letter}:\\{rest_of_path}"
                formatted_dirs.append(formatted_dir)
            directories_data.extend(formatted_dirs)

        formatted_resources = []
        for name in self.filenames:
            formatted_name = name
            volume_match = volume_pattern.search(name)
            if volume_match:
                volume_id = volume_match.group(0)
                drive_letter = drive_letters.get(volume_id)
                if not drive_letter:
                    for vol in self.volume_information:
                        if volume_id in vol.device_name:
                            drive_letter = drive_letters.get(vol.device_name)
                            if drive_letter:
                                break
                if drive_letter:
                    rest_of_path = name[volume_match.end():].lstrip("\\")
                    formatted_name = f"{drive_letter}:\\{rest_of_path}"
            formatted_resources.append(formatted_name)

        run_times_data = [str(t) for t in sorted([t for t in self.last_run_times if t is not None], reverse=True)]

        return {
            "filename": filename,
            "executable_name": self.header.executable_filename,
            "hash": self.header.hash,
            "run_count": self.run_count,
            "last_executed": str(most_recent) if most_recent else None,
            "run_times": run_times_data,
            "volumes": volumes_data,
            "directories": directories_data,
            "resources": formatted_resources,
            "created_on": str(self.source_created_on) if self.source_created_on else None,
            "modified_on": str(self.source_modified_on) if self.source_modified_on else None,
            "accessed_on": str(self.source_accessed_on) if self.source_accessed_on else None
        }

    def save_to_sqlite(self, db_path: str):
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("PRAGMA integrity_check")
            conn.close()
        except sqlite3.DatabaseError:
            print(f"Database at {db_path} is malformed. Recreating database...")
            try:
                os.remove(db_path)
            except OSError as e:
                print(f"Error removing corrupted database: {e}")
                return

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prefetch_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    executable_name TEXT,
                    hash TEXT,
                    run_count INTEGER,
                    last_executed TIMESTAMP,
                    run_times JSON,
                    volumes JSON,
                    directories JSON,
                    resources JSON,
                    created_on TIMESTAMP,
                    modified_on TIMESTAMP,
                    accessed_on TIMESTAMP
                )
            """)

            data = self.get_data_dict()
            
            cursor.execute("""
                INSERT INTO prefetch_data (
                    filename, executable_name, hash, run_count, last_executed,
                    run_times, volumes, directories, resources,
                    created_on, modified_on, accessed_on
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["filename"],
                data["executable_name"],
                data["hash"],
                data["run_count"],
                data["last_executed"],
                json.dumps(data["run_times"]),
                json.dumps(data["volumes"]),
                json.dumps(data["directories"]),
                json.dumps(data["resources"]),
                data["created_on"],
                data["modified_on"],
                data["accessed_on"]
            ))

            conn.commit()
        except sqlite3.DatabaseError as e:
            logging.error(f"Database error for {db_path}: {e}")
            print(f"Database error: {e}")
        finally:
            conn.close()

    def save_to_json(self, json_path: str, data_list: list):
        try:
            with open(json_path, 'w') as f:
                json.dump(data_list, f, indent=2)
        except Exception as e:
            logging.error(f"Error writing to JSON file {json_path}: {e}")
            print(f"Error writing to JSON file: {e}")

    def save_to_csv(self, csv_path: str, data_list: list):
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "filename", "executable_name", "hash", "run_count", "last_executed",
                    "run_times", "volumes", "directories", "resources", "created_on",
                    "modified_on", "accessed_on"
                ])
                writer.writeheader()
                for data in data_list:
                    writer.writerow({
                        "filename": data["filename"],
                        "executable_name": data["executable_name"],
                        "hash": data["hash"],
                        "run_count": data["run_count"],
                        "last_executed": data["last_executed"],
                        "run_times": json.dumps(data["run_times"]),
                        "volumes": json.dumps(data["volumes"]),
                        "directories": json.dumps(data["directories"]),
                        "resources": json.dumps(data["resources"]),
                        "created_on": data["created_on"],
                        "modified_on": data["modified_on"],
                        "accessed_on": data["accessed_on"]
                    })
        except Exception as e:
            logging.error(f"Error writing to CSV file {csv_path}: {e}")
            print(f"Error writing to CSV file: {e}")

    def __str__(self) -> str:
        result = []

        filename = os.path.basename(self.source_filename) if self.source_filename else "Unknown"
        result.append(f"Prefetch File: {filename}")

        result.append(f"Executable Name: {self.header.executable_filename}")
        result.append(f"Hash: {self.header.hash}")

        result.append(f"Run Count: {self.run_count}")

        if self.last_run_times and len(self.last_run_times) > 0:
            most_recent = max([t for t in self.last_run_times if t is not None], default=None)
            if most_recent:
                result.append(f"Last Executed: {most_recent}")
        
            valid_times = [t for t in self.last_run_times if t is not None]
            if len(valid_times) > 1:
                result.append("Execution Timeline:")
                for i, time in enumerate(sorted(valid_times, reverse=True), 1):
                    result.append(f"  {i}. {time}")

        if self.volume_information:
            result.append("Volume Information:")
        
            drive_letters = {}
            volume_pattern = re.compile(r'\\VOLUME\{[0-9a-f-]+\}', re.IGNORECASE)
        
            for vol in self.volume_information:
                if "Drive" in vol.device_name and ":" in vol.device_name:
                    match = re.search(r'Drive ([A-Z]):', vol.device_name)
                    if match:
                        drive_letter = match.group(1)
                        drive_letters[vol.device_name] = drive_letter
                        volume_match = volume_pattern.search(vol.device_name)
                        if volume_match:
                            volume_id = volume_match.group(0)
                            drive_letters[volume_id] = drive_letter

            for i, vol in enumerate(self.volume_information, 1):
                drive_letter = drive_letters.get(vol.device_name)
                vol_id = f"{drive_letter}:" if drive_letter else f"Volume{i}"
                result.append(f"Volume {vol_id}:")
                result.append(f"  Device Name: {vol.device_name}")
                result.append(f"  Creation Date: {vol.creation_time}")
                result.append(f"  Serial Number: {vol.serial_number}")
            
                if vol.directory_names:
                    result.append(f"  Directories Referenced:")
                    formatted_dirs = []
                    for dir_name in vol.directory_names:
                        formatted_dir = dir_name
                        volume_match = volume_pattern.search(dir_name)
                        if volume_match and drive_letter:
                            volume_id = volume_match.group(0)
                            rest_of_path = dir_name[volume_match.end():].lstrip("\\")
                            formatted_dir = f"{drive_letter}:\\{rest_of_path}"
                        formatted_dirs.append(formatted_dir)
                    for dir_path in formatted_dirs:
                        result.append(f"    {dir_path}")

        if self.filenames:
            result.append("Resources Loaded:")
            formatted_resources = []
            for name in self.filenames:
                formatted_name = name
                volume_match = volume_pattern.search(name)
                if volume_match:
                    volume_id = volume_match.group(0)
                    drive_letter = drive_letters.get(volume_id)
                    if not drive_letter:
                        for vol in self.volume_information:
                            if volume_id in vol.device_name:
                                drive_letter = drive_letters.get(vol.device_name)
                                if drive_letter:
                                    break
                    if drive_letter:
                        rest_of_path = name[volume_match.end():].lstrip("\\")
                        formatted_name = f"{drive_letter}:\\{rest_of_path}"
                formatted_resources.append(formatted_name)
        
            for i, name in enumerate(formatted_resources, 1):
                result.append(f"  {i}. {name}")

        return "\n".join(result)

    @staticmethod
    def _get_readable_volume_name(device_name, serial_number):
        guid_match = re.search(r'\{([0-9a-f-]+)\}', device_name, re.IGNORECASE)
        
        if guid_match:
            guid = guid_match.group(1)
            
            if os.name == 'nt':
                try:
                    from ctypes.wintypes import DWORD, LPCWSTR, LPWSTR
                    
                    DRIVE_UNKNOWN = 0
                    DRIVE_REMOVABLE = 2
                    DRIVE_FIXED = 3
                    DRIVE_REMOTE = 4
                    DRIVE_CDROM = 5
                    DRIVE_RAMDISK = 6
                    
                    drives = []
                    bitmask = windll.kernel32.GetLogicalDrives()
                    for letter in range(ord('A'), ord('Z')+1):
                        if bitmask & 1:
                            drives.append(chr(letter))
                        bitmask >>= 1
                    
                    for drive in drives:
                        drive_path = f"{drive}:\\"
                        
                        drive_type = windll.kernel32.GetDriveTypeW(LPCWSTR(drive_path))
                        
                        vol_name_buf = ctypes.create_unicode_buffer(1024)
                        fs_name_buf = ctypes.create_unicode_buffer(1024)
                        serial_num = DWORD(0)
                        
                        result = windll.kernel32.GetVolumeInformationW(
                            LPCWSTR(drive_path),
                            vol_name_buf,
                            ctypes.sizeof(vol_name_buf),
                            ctypes.byref(serial_num),
                            None,
                            None,
                            fs_name_buf,
                            ctypes.sizeof(fs_name_buf)
                        )
                        
                        if result:
                            drive_serial = format(serial_num.value, '08X')
                            
                            if drive_serial == serial_number:
                                vol_label = vol_name_buf.value
                                drive_type_str = {
                                    DRIVE_UNKNOWN: "Unknown",
                                    DRIVE_REMOVABLE: "Removable",
                                    DRIVE_FIXED: "Fixed",
                                    DRIVE_REMOTE: "Network",
                                    DRIVE_CDROM: "CD-ROM",
                                    DRIVE_RAMDISK: "RAM Disk"
                                }.get(drive_type, "Unknown")
                                
                                if vol_label:
                                    return f"Drive {drive}: '{vol_label}' ({drive_type_str})"
                                else:
                                    return f"Drive {drive}: ({drive_type_str})"
                
                    return None
                    
                except Exception as e:
                    logging.warning(f"Error getting volume information: {e}")
                    return f"Volume ID: {guid}"
            
            return f"Volume ID: {guid}"
        
        return None

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_output_path(output_format):
    default_paths = {"sqlite": DB_PATH, "json": JSON_PATH, "csv": CSV_PATH}
    custom_path = input(f"Enter output path for {output_format.upper()} (default: {default_paths[output_format]}): ").strip()
    return custom_path or default_paths[output_format]

def parse_file(args):
    directory, filename = args
    try:
        file_path = os.path.join(directory, filename)
        if os.path.getsize(file_path) < 84:
            logging.warning(f"File {file_path} is too small to be a valid prefetch file")
            return None
        prefetch = PrefetchFile.open(file_path)
        return prefetch.get_data_dict()
    except Exception as e:
        logging.error(f"Failed to parse {filename}: {e}")
        return None

def process_prefetch_files(directory, output_format, output_path):
    parsed_files = []
    total_pf_files = 0
    data_list = []

    try:
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"Prefetch directory not found: {directory}")
        
        # Count total .pf files for progress bar
        pf_files = [f for f in os.listdir(directory) if f.lower().endswith('.pf')]
        total_pf_files = len(pf_files)
        
        print(f"\nProcessing {total_pf_files} prefetch files...")
        with Pool() as pool:
            with tqdm(total=total_pf_files, desc="Parsing Files", unit="file") as pbar:
                for result in pool.imap_unordered(parse_file, [(directory, f) for f in pf_files]):
                    pbar.set_postfix(file=pf_files[pbar.n] if pbar.n < len(pf_files) else "Done")
                    if result:
                        data_list.append(result)
                        parsed_files.append(result["filename"])
                    pbar.update(1)
        
        if output_format == "sqlite":
            for data in data_list:
                prefetch = PrefetchFile()
                prefetch.source_filename = data["filename"]
                prefetch.header = Header(
                    version=Version.WIN10_OR_WIN11,  # Dummy value, not used in save
                    signature="",
                    file_size=0,
                    executable_filename=data["executable_name"],
                    hash=data["hash"]
                )
                prefetch.last_run_times = [datetime.datetime.fromisoformat(t) for t in data["run_times"] if t]
                prefetch.run_count = data["run_count"] or 0
                prefetch.source_created_on = datetime.datetime.fromisoformat(data["created_on"]) if data["created_on"] else None
                prefetch.source_modified_on = datetime.datetime.fromisoformat(data["modified_on"]) if data["modified_on"] else None
                prefetch.source_accessed_on = datetime.datetime.fromisoformat(data["accessed_on"]) if data["accessed_on"] else None
                prefetch.volume_information = [
                    VolumeInfo(
                        device_name_offset=0,
                        creation_time=datetime.datetime.fromisoformat(vol["creation_time"]) if vol["creation_time"] else None,
                        serial_number=vol["serial_number"],
                        device_name=vol["device_name"]
                    ) for vol in data["volumes"]
                ]
                prefetch.filenames = data["resources"]
                prefetch.save_to_sqlite(output_path)
        elif output_format == "json":
            PrefetchFile().save_to_json(output_path, data_list)
        elif output_format == "csv":
            PrefetchFile().save_to_csv(output_path, data_list)
        
        print(f"\nPercentage of Successfully Parsed Files: {(len(parsed_files) / total_pf_files * 100) if total_pf_files > 0 else 0:.2f}%")
        if os.path.exists(LOG_FILE):
            print(f"Parsing errors logged to {LOG_FILE}")
    except Exception as e:
        logging.error(f"Error accessing prefetch directory {directory}: {e}")
        print(f"\nError accessing prefetch directory: {e}")

def display_menu(options, menu_type="main"):
    print(f"\n=== CROW-EYE PREFETCH ANALYZER {'MENU' if menu_type == 'main' else 'OUTPUT FORMAT'} ===")
    for i, option in enumerate(options, 1):
        print(f"{i}. {option}")

def select_output_format():
    options = ["SQLite Database", "JSON File", "CSV File", "Back"]
    while True:
        display_menu(options, menu_type="output")
        print("\nEnter a number (1-4) to select output format: ")
        choice = input().strip()
        if choice in ['1', '2', '3', '4']:
            if choice == '1':
                return "sqlite", get_output_path("sqlite")
            elif choice == '2':
                return "json", get_output_path("json")
            elif choice == '3':
                return "csv", get_output_path("csv")
            elif choice == '4':
                return None, None
        else:
            print("Invalid input. Please enter a number between 1 and 4.")
            input("Press Enter to continue...")

def main():
    print(LOGO)
    
    if not is_admin():
        print("This program requires administrative privileges.")
        input("Please run as administrator and press Enter to exit...")
        return
    
    options = [
        "Live Analysis (C:\\Windows\\Prefetch)",
        "Offline Analysis (Custom Directory)",
        "Select Output Format",
        "Exit"
    ]
    output_format = "sqlite"
    output_path = DB_PATH
    
    while True:
        display_menu(options)
        print(f"\nCurrent output format: {output_format.upper()} ({output_path})")
        print("Enter a number (1-4) to select an option: ")
        choice = input().strip()
        
        if choice in ['1', '2', '3', '4']:
            if choice == '1':
                print(f"\nPerforming live analysis on {PREFETCH_DIR}...")
                process_prefetch_files(PREFETCH_DIR, output_format, output_path)
                input("\nPress Enter to continue...")
            elif choice == '2':
                custom_dir = input("\nEnter the path to the prefetch directory: ").strip()
                if os.path.isdir(custom_dir):
                    print(f"\nPerforming offline analysis on {custom_dir}...")
                    process_prefetch_files(custom_dir, output_format, output_path)
                    input("\nPress Enter to continue...")
                else:
                    print(f"\nError: {custom_dir} is not a valid directory.")
                    input("\nPress Enter to continue...")
            elif choice == '3':
                new_format, new_path = select_output_format()
                if new_format and new_path:
                    output_format = new_format
                    output_path = new_path
                    print(f"\nOutput format set to {output_format.upper()} ({output_path})")
                    input("\nPress Enter to continue...")
            elif choice == '4':
                print("\nExiting CROW-EYE PREFETCH ANALYZER...")
                break
        else:
            print("Invalid input. Please enter a number between 1 and 4.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
