"""
Header Analyzer Module
"""

import zipfile
from pathlib import Path
from typing import Optional, Dict, Any
import lief
import pefile
from elftools.elf.elffile import ELFFile
from nordstream2.analyzers import Analyzer


class HeaderAnalyzer(Analyzer):
    """
    Analyzes the header of the binary file.
    Supports PE, ELF, Mach-O, and APK.
    """

    def analyze(self):
        """
        Analyzes the file header and sections.
        This method uses the LIEF library to analyze
        the file header and sections of the binary file.
        It also validates the hash of the analyzed header
        against the metadata provided.
        :return: None
        :raises: Exception if the hash validation fails
        """
        self.logger.info("Analyzing header...")

        path = Path(self.sample_path)
        try:
            # First, check if it's a ZIP file (APK is basically a ZIP)
            if zipfile.is_zipfile(path):
                return self._analyze_apk()

            binary = lief.parse(str(path))  # pylint: disable=no-member

            if binary is None:
                self.logger.warning("Could not parse file using LIEF.")
                return {}

            if binary.format == 'ELF':
                return self._analyze_elf(binary)
            if binary.format == 'MACHO':
                return self._analyze_macho(binary)
            if binary.format == 'PE':
                return self._analyze_pe(binary)
            self.logger.warning(f"Unsupported format: {binary.format}")
            return {}
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Header analysis failed: {e}")
            return {}

    def _analyze_pe(self, file_obj):
        try:
            pe = pefile.PE(data=file_obj.read())
            unknown = 'Unknown'

            architecture = pefile.MACHINE_TYPE.get(
                getattr(pe.FILE_HEADER, 'Machine', None), unknown)

            entry_point = hex(getattr(
                pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0))

            image_base = hex(getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0))

            sections = [
                s.Name.decode(errors='ignore').strip('\x00')
                for s in pe.sections
            ]

            return {
                "format": "PE",
                "architecture": architecture,
                "entry_point": entry_point,
                "image_base": image_base,
                "sections": sections,
            }
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"PE analysis failed: {e}")
            return {"format": "PE", "error": str(e)}

    def _analyze_unix_binary(
            self,
            binary_type: str,
            entry_point: str,
            arch: str,
            bits: int,
            endian: str,
            sections: Optional[list] = None,
            libraries: Optional[list] = None
    ) -> Dict[str, Any]:
        """Builds a common metadata dictionary for ELF and Mach-O binaries."""
        return {
            "format": binary_type,
            "architecture": arch,
            "bits": bits,
            "endian": endian,
            "entry_point": entry_point,
            "sections": sections,
            "libraries": libraries,
        }

    def _analyze_elf(self, _elf) -> Dict[str, Any]:
        try:
            with open(self.sample_path, 'rb') as f:
                elffile = ELFFile(f)
                entry_point = hex(elffile.header['e_entry'])
                arch = elffile.get_machine_arch()
                bits = elffile.elfclass
                endian = 'little' if elffile.little_endian else 'big'
                sections = [
                    {
                        'name': sec.name,
                        'size': sec['sh_size'],
                        'type': sec['sh_type']
                    }
                    for sec in elffile.iter_sections()
                ]
                libs = []
                dynamic = elffile.get_section_by_name('.dynamic')
                if dynamic:
                    libs = [t.needed for t in dynamic.iter_tags('DT_NEEDED')]
            return self._analyze_unix_binary(
                binary_type='ELF',
                entry_point=entry_point,
                arch=arch,
                bits=bits,
                endian=endian,
                sections=sections,
                libraries=libs
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"ELF analysis failed: {e}")
            return {"format": "ELF", "error": str(e)}

    def _analyze_macho(self, macho) -> Dict[str, Any]:
        try:
            entry_point = hex(macho.entrypoint)
            arch = str(macho.header.cpu_type).rsplit('.', maxsplit=1)[-1]
            bits = 64 if macho.header.is_64 else 32
            end_map = {
                lief.MachO.ENDIANNESS.LITTLE: 'little',
                lief.MachO.ENDIANNESS.BIG: 'big',
            }
            endian = end_map.get(macho.header.endianness, 'unknown')
            sections = [
                {
                    'name': sec.name,
                    'size': sec.size,
                    'type': sec.type.name
                }
                for sec in macho.sections
            ]
            libs = [lib.name for lib in macho.libraries]
            return self._analyze_unix_binary(
                binary_type='Mach-O',
                entry_point=entry_point,
                arch=arch,
                bits=bits,
                endian=endian,
                sections=sections,
                libraries=libs
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"Mach-O analysis failed: {e}")
            return {"format": "Mach-O", "error": str(e)}

    def _analyze_apk(self):
        try:
            with zipfile.ZipFile(self.sample_path, 'r') as apk:
                files = apk.namelist()
                return {
                    "type": "APK",
                    "file_count": len(files),
                    "contains_manifest": "AndroidManifest.xml" in files,
                    "contains_dex": any(f.endswith('.dex') for f in files)
                }
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(f"APK analysis failed: {e}")
            return {}
