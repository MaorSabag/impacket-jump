# -*- coding: utf-8 -*-

# Standard Library Imports
import sys
import os
import argparse
import logging
import time
import types

# Impacket Imports
from impacket.examples import logger
from impacket import version
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, scmr
from impacket.examples.utils import parse_target

STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
REMOTE_CWD = 'C:\\'

service_types = {
    scmr.SERVICE_KERNEL_DRIVER: 'Kernel Driver',
    scmr.SERVICE_FILE_SYSTEM_DRIVER: 'File System Driver',
    scmr.SERVICE_WIN32_OWN_PROCESS: 'Win32 Own Process',
    scmr.SERVICE_WIN32_SHARE_PROCESS: 'Win32 Share Process',
    scmr.SERVICE_INTERACTIVE_PROCESS: 'Interactive Process',
    scmr.SERVICE_NO_CHANGE: 'No Change',
}

service_start_types = {
    scmr.SERVICE_BOOT_START: 'Boot Start',
    scmr.SERVICE_SYSTEM_START: 'System Start',
    scmr.SERVICE_AUTO_START: 'Auto Start',
    scmr.SERVICE_DEMAND_START: 'Demand Start',
    scmr.SERVICE_DISABLED: 'Disabled',
    scmr.SERVICE_NO_CHANGE: 'No Change',
}

service_error_control = {
    scmr.SERVICE_ERROR_IGNORE: 'Ignore',
    scmr.SERVICE_ERROR_NORMAL: 'Normal',
    scmr.SERVICE_ERROR_SEVERE: 'Severe',
    scmr.SERVICE_ERROR_CRITICAL: 'Critical',
    scmr.SERVICE_NO_CHANGE: 'No Change',
}


def _parse_remote_path(remote_path, local_hint=None):
    global REMOTE_CWD
    original = (remote_path or '').strip()
    cleaned = original.replace('/', '\\')

    share = None
    remainder = ''

    if cleaned.startswith('\\\\'):
        cleaned = cleaned[2:]
        parts = cleaned.split('\\', 2)
        if len(parts) < 2:
            raise ValueError('UNC path must include a share and file path')
        # parts[0] is host, parts[1] is share
        share = parts[1]
        if len(parts) > 2:
            remainder = parts[2]
    elif len(cleaned) >= 2 and cleaned[1] == ':':
        full_path = os.path.normpath(cleaned)
        share = f'{full_path[0].upper()}$'
        remainder = full_path[2:]
    elif cleaned:
        parts = cleaned.split('\\', 1)
        candidate_share = parts[0]
        if candidate_share.endswith('$') and len(parts) > 1:
            share = candidate_share
            remainder = parts[1]
        elif candidate_share.endswith('$') and len(parts) == 1:
            share = candidate_share
            remainder = ''
        else:
            base = REMOTE_CWD or 'C:\\'
            full_path = os.path.normpath(os.path.join(base, cleaned))
            share = f'{full_path[0].upper()}$'
            remainder = full_path[2:]
    else:
        base = REMOTE_CWD or 'C:\\'
        full_path = os.path.normpath(base)
        share = f'{full_path[0].upper()}$'
        remainder = full_path[2:]

    remainder = remainder.lstrip('\\')
    dir_hint = False
    if local_hint is not None:
        if original == '' or original.endswith(('\\', '/')) or original in ('.', '..'):
            dir_hint = True

    if not remainder:
        if local_hint is None:
            raise ValueError('Remote path must include a file name')
        remainder = os.path.basename(local_hint)
    elif dir_hint:
        remainder = os.path.join(remainder, os.path.basename(local_hint))

    remainder = remainder.replace('/', '\\')

    share_path = '\\' + remainder.lstrip('\\')
    share_path = os.path.normpath(share_path)
    if share_path in ('', '.'):  # pragma: no cover - sanity check
        raise ValueError('Remote path must include a file name')
    return share, share_path


def hRChangeServiceConfig2W(dce, lpServiceName, dwInfoLevel, lpInfo):
    request = scmr.RChangeServiceConfig2W()
    
    Info = scmr.SC_RPC_CONFIG_INFOW()
    Info['dwInfoLevel'] = dwInfoLevel
    
    Union = scmr.SC_RPC_CONFIG_INFOW_UNION()
    Union['tag'] = dwInfoLevel
    if dwInfoLevel == scmr.SERVICE_CONFIG_DESCRIPTION:
        psd = scmr.LPSERVICE_DESCRIPTIONW()
        service_description = scmr.SERVICE_DESCRIPTIONW()
        service_description['lpDescription'] = lpInfo

        psd['Data'] = service_description
        Union['psd'] = psd
    else:
        raise NotImplementedError('InfoLevel %d not implemented' % dwInfoLevel)

    Info['Union'] = Union

    request['hService'] = lpServiceName
    request['Info'] = Info
    
    return dce.request(request)


def _ensure_remote_dirs(conn, share, share_path):
    components = share_path.strip('\\').split('\\')
    if len(components) <= 1:
        return
    partial = ''
    for segment in components[:-1]:
        partial = f'{partial}\\{segment}' if partial else f'\\{segment}'
        try:
            conn.createDirectory(share, partial)
        except SessionError as exc:
            if exc.getErrorCode() != STATUS_OBJECT_NAME_COLLISION:
                raise


def _split_share_path(share_path):
    cleaned = (share_path or '').strip().replace('/', '\\')
    cleaned = cleaned.strip('\\')
    if not cleaned:
        raise ValueError('Share path cannot be empty')
    parts = cleaned.split('\\', 1)
    share_name = parts[0]
    subpath = parts[1] if len(parts) > 1 else ''
    subpath = subpath.strip('\\')
    return share_name, subpath


class JUMP:
    def __init__(self, exeFile, port=445, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, target='',
                 serviceName='', serviceDisplayName='', serviceDescription=None, serviceArgs=None, remoteBinaryName=None, sharePath='', pipeName=None):
        self.__exeFile = exeFile
        self.__port = port
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__target = target
        self.__serviceName = serviceName
        self.__serviceDisplayName = serviceDisplayName
        self.__serviceDescription = serviceDescription
        self.__serviceArgs = serviceArgs
        self.__remoteBinaryName = remoteBinaryName
        self.__sharePath = sharePath
        self.__pipeName = pipeName
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        

    def _configure_installer_for_share(self, installer):
        if not self.__sharePath:
            return

        share_name, share_subpath = _split_share_path(self.__sharePath)
        remote_relative_path = self.__remoteBinaryName
        if share_subpath:
            remote_relative_path = f'{share_subpath}\\{remote_relative_path}'

        # Ensure the destination directories exist before upload
        _ensure_remote_dirs(installer.connection, share_name, f'\\{remote_relative_path}')

        logging.info('Using specified share path: share=%s, subpath=%s', share_name, share_subpath or '<root>')

        installer.share = share_name
        setattr(installer, '_ServiceInstall__binary_service_name', remote_relative_path)

        def _fixed_find_writable_share(self_inst, _shares):  # pylint: disable=unused-argument
            return share_name

        installer.findWritableShare = types.MethodType(_fixed_find_writable_share, installer)
    

    def _remove_uploaded_binary(self, connection: SMBConnection):
        # try to remove the uploaded binary with 3 tries
        for i in range(3):
            try:
                share, remote_path = _parse_remote_path(self.__sharePath, local_hint=self.__remoteBinaryName)
                connection.deleteFile(share, f"{remote_path}\\{self.__remoteBinaryName}")
                logging.info('Removed uploaded binary %s\\%s\\%s', share, remote_path, self.__remoteBinaryName)
                break
            except Exception as cleanup_exc:
                if i == 2:
                    logging.error('Failed removing uploaded binary: %s', cleanup_exc)
                time.sleep(0.3)


    def _read_from_pipe(self, remoteHost):
        logging.info(f'Connecting to pipe {self.__pipeName} on {remoteHost}...')
        try:
            conn = SMBConnection(remoteHost, remoteHost, sess_port=self.__port)
            if self.__doKerberos:
                conn.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__kdcHost)
            else:
                conn.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            
            tid = conn.connectTree('IPC$')
            
            fid = None
            # Try for 10 seconds
            for _ in range(20):
                try:
                    # FILE_READ_DATA = 1
                    fid = conn.openFile(tid, self.__pipeName, 1, creationOption=0x40, fileAttributes=0x80)
                    break
                except Exception:
                    time.sleep(0.5)
            
            if fid is None:
                logging.error(f'Could not connect to pipe {self.__pipeName} after retries.')
                conn.logoff()
                return

            logging.info(f'Connected to pipe {self.__pipeName}. Reading output...')
            
            while True:
                try:
                    data = conn.readFile(tid, fid, 0, 1024)
                    if len(data) == 0:
                        break
                    sys.stdout.write(data.decode('cp437', errors='replace'))
                    sys.stdout.flush()
                except SessionError as e:
                    if e.getErrorCode() == 0xC000014B or e.getErrorCode() == 0xc00000b0: # STATUS_PIPE_BROKEN or STATUS_PIPE_DISCONNECTED
                        break
                    raise

            conn.closeFile(tid, fid)
            conn.logoff()
            
        except Exception as e:
             
             logging.error(f'Error reading from pipe: {e}')


    def create_service(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        smb_conn = None

        try:
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            smb_conn = rpctransport.get_smb_connection()
            smb_conn.setTimeout(100000)

            with open(self.__exeFile, 'rb') as f:
                # first Upload the binary to the target system
                logging.info('Uploading binary %s to target %s', self.__exeFile, remoteHost)
                if self.__sharePath:
                    share_name, share_subpath = _split_share_path(self.__sharePath)
                    remote_relative_path = self.__remoteBinaryName
                    if share_subpath:
                        remote_relative_path = f'{share_subpath}\\{remote_relative_path}'

                    # Ensure the destination directories exist before upload
                    _ensure_remote_dirs(smb_conn, share_name, f'\\{remote_relative_path}')

                    logging.info('Using specified share path: share=%s, subpath=%s', share_name, share_subpath or '<root>')

                    remote_path = f'\\{remote_relative_path}'
                    smb_conn.putFile(share_name, remote_path, f.read)
                    display_remote_path = f'{share_name}\\{remote_relative_path}'
                    logging.info('Successfully uploaded binary to %s', display_remote_path)
                else:
                    # Find a writable share
                    shares = smb_conn.listShares()
                    writable_share = None
                    for share in shares:
                        share_name = share['shi1_netname'][:-1]
                        try:
                            smb_conn.putFile(share_name, f'\\{self.__remoteBinaryName}', f.read)
                            writable_share = share_name
                            display_remote_path = f'{writable_share}\\{self.__remoteBinaryName}'
                            logging.info('Successfully uploaded binary to %s', display_remote_path)
                            break
                        except Exception:
                            f.seek(0)
                            continue
                    if not writable_share:
                        logging.error('No writable share found on target %s', remoteHost)
                        return
            # Now create the service
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                service_handle = scmr.hRCreateServiceW(
                    dce=dce,
                    hSCManager=svc_manager,
                    lpServiceName=self.__serviceName + '\x00',
                    lpDisplayName=self.__serviceDisplayName + '\x00',
                    lpBinaryPathName=f'\\\\{remoteHost}\\{display_remote_path}\x00',
                    dwStartType=scmr.SERVICE_DEMAND_START
                )['lpServiceHandle']

                logging.info(f'Created service {self.__serviceName} (manual start) referencing \\\\{remoteHost}\\{display_remote_path}')

                if self.__serviceDescription:
                    # Change service description
                    hRChangeServiceConfig2W(
                        dce,
                        service_handle,
                        scmr.SERVICE_CONFIG_DESCRIPTION,
                        self.__serviceDescription + '\x00'
                    )

            except Exception as create_exc:
                logging.error('Failed to create service on %s: %s', remoteHost, create_exc)
                self.__remove_uploaded_binary(smb_conn)
                raise
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)     
 
        except FileNotFoundError:
            logging.critical('The specified executable file %s was not found.', self.__exeFile)
            sys.exit(1)
        except Exception as e:
            if '_remove_uploaded_binary' in locals():
                try:
                    self._remove_uploaded_binary(smb_conn)
                except Exception:
                    pass
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass


    def start_service(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                resp = scmr.hROpenServiceW(dce, svc_manager, self.__serviceName + '\x00')
            except Exception as exc:
                scmr.hRCloseServiceHandle(dce, svc_manager)
                logging.error('Failed opening service %s: %s', self.__serviceName, exc)
                sys.exit(1)

            service_handle = resp['lpServiceHandle']
            try:
                if self.__serviceArgs:
                    args_list = self.__serviceArgs.split()
                    scmr.hRStartServiceW(dce, service_handle, len(args_list), args_list)
                else:
                    scmr.hRStartServiceW(dce, service_handle)
                    
                logging.info(f'Service {self.__serviceName} started successfully on {remoteHost}')

                if self.__pipeName:
                    self._read_from_pipe(remoteHost)

            except Exception as start_exc:
                logging.error('Failed to start service on %s: %s', remoteHost, start_exc)
                raise
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)
            
        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass        
            

    def stop_service(self, remoteName, remoteHost, dce=None):
        if dce is None:
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
            logging.debug('StringBinding %s' % stringbinding)
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.__port)
            rpctransport.setRemoteHost(remoteHost)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
        try:
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                resp = scmr.hROpenServiceW(dce, svc_manager, self.__serviceName + '\x00')
            except Exception as exc:
                scmr.hRCloseServiceHandle(dce, svc_manager)
                logging.error('Failed opening service %s: %s', self.__serviceName, exc)
                sys.exit(1)

            # Stop the service
            service_handle = resp['lpServiceHandle']
            try:
                scmr.hRControlService(dce, service_handle, scmr.SERVICE_CONTROL_STOP)
                logging.info(f'Service {self.__serviceName} stopped successfully on {remoteHost}')
            except Exception as delete_exc:
                if 'code: 0x426' in str(delete_exc):
                    logging.info(f'Service {self.__serviceName} is not running on {remoteHost}')
                else:
                    logging.error('Failed to delete service on %s: %s', remoteHost, delete_exc)
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)
        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)
    

    def delete_service(self, remoteName, remoteHost, dce=None):
        if dce is None:
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
            logging.debug('StringBinding %s' % stringbinding)
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.__port)
            rpctransport.setRemoteHost(remoteHost)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
        try:
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                resp = scmr.hROpenServiceW(dce, svc_manager, self.__serviceName + '\x00')
            except Exception as exc:
                scmr.hRCloseServiceHandle(dce, svc_manager)
                logging.error('Failed opening service %s: %s', self.__serviceName, exc)
                sys.exit(1)
            # Delete the service
            service_handle = resp['lpServiceHandle']
            try:
                scmr.hRDeleteService(dce, service_handle)
                logging.info(f'Service {self.__serviceName} deleted successfully on {remoteHost}')
            except Exception as delete_exc:
                logging.error('Failed to delete service on %s: %s', remoteHost, delete_exc)
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)
        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)
        

    def cleanup_service(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        self.stop_service(remoteName, remoteHost, dce)
        self.delete_service(remoteName, remoteHost, dce)
        self._remove_uploaded_binary(rpctransport.get_smb_connection())


    def _get_service_info(self, remoteName, remoteHost) -> scmr.QUERY_SERVICE_CONFIGW:
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                resp = scmr.hROpenServiceW(dce, svc_manager, self.__serviceName + '\x00', scmr.SERVICE_QUERY_CONFIG)
            except Exception as exc:
                scmr.hRCloseServiceHandle(dce, svc_manager)
                logging.error('Failed opening service %s: %s', self.__serviceName, exc)
                sys.exit(1)

            service_handle = resp['lpServiceHandle']
            try:
                config = scmr.hRQueryServiceConfigW(dce, service_handle)
                lpServiceConfig: scmr.QUERY_SERVICE_CONFIGW = config['lpServiceConfig']
                return lpServiceConfig
            except Exception as query_exc:
                logging.error('Failed to query service on %s: %s', remoteHost, query_exc)
                raise
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)
        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)
        
    def print_service_info(self, remoteName, remoteHost):
        config: scmr.QUERY_SERVICE_CONFIGW = self._get_service_info(remoteName, remoteHost)
        logging.info('Service Name: %s', self.__serviceName)
        logging.info('Display Name: %s', config['lpDisplayName'][:-1])
        logging.info('Binary Path: %s', config['lpBinaryPathName'][:-1])
        logging.info('Service Type: %s', service_types.get(config['dwServiceType'], 'UNKNOWN'))
        logging.info('Start Type: %s', service_start_types.get(config['dwStartType'], 'UNKNOWN'))
        logging.info('Error Control: %s', service_error_control.get(config['dwErrorControl'], 'UNKNOWN'))
    

    def change_service_info(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            svc_manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service_handle = None
            try:
                resp = scmr.hROpenServiceW(dce, svc_manager, self.__serviceName + '\x00', scmr.SERVICE_CHANGE_CONFIG)
            except Exception as exc:
                scmr.hRCloseServiceHandle(dce, svc_manager)
                logging.error('Failed opening service %s: %s', self.__serviceName, exc)
                sys.exit(1)

            service_handle = resp['lpServiceHandle']
            try:
                # Currently only service description change is implemented
                if self.__serviceDescription:
                    hRChangeServiceConfig2W(
                        dce,
                        service_handle,
                        scmr.SERVICE_CONFIG_DESCRIPTION,
                        self.__serviceDescription + '\x00'
                    )
                    logging.info(f'Service {self.__serviceName} description changed successfully on {remoteHost}')
                
                if self.__serviceDisplayName or self.__serviceName:
                    scmr.hRChangeServiceConfigW(
                        dce=dce,
                        hService=service_handle,
                        lpDisplayName=(self.__serviceDisplayName + '\x00') if self.__serviceDisplayName else None,
                        dwServiceType=scmr.SERVICE_NO_CHANGE,
                        dwStartType=scmr.SERVICE_NO_CHANGE,
                        dwErrorControl=scmr.SERVICE_NO_CHANGE,
                        lpBinaryPathName=self.__remoteBinaryName if self.__remoteBinaryName else None,
                    )
                    logging.info(f'Service {self.__serviceName} configuration changed successfully on {remoteHost}')
            except Exception as change_exc:
                logging.error('Failed to change service on %s: %s', remoteHost, change_exc)
                raise
            finally:
                if service_handle is not None:
                    scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, svc_manager)
        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical('An error occurred: %s', str(e))
            sys.exit(1)


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser( add_help = True, description = "Impacket Jump Tool for handling service implants" )
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='Don\'t ask for password (useful for -hashes)')
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file or KRB5CCNAME environment variable if set.')
    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar='ip address', help='IP Address of the target machine')
    group.add_argument('-port', choices=['139', '445'], default='445', help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('service settings')
    group.add_argument('-file', '--service-exe', dest='service_exe', help='Path to the service executable to upload and run on the target system')
    group.add_argument('-service-name', action='store', default='ImpacketJumpService', help='Name of the service to create (default: ImpacketJumpService)')
    group.add_argument('-service-display-name', action='store', default='Impacket Jump Service', help='Display name of the service to create (default: Impacket Jump Service)')
    group.add_argument('-service-description', action='store', help='Description of the service to create (default: Impacket Jump Service created by impacket-jump.py)')
    group.add_argument('-service-args', action='store', default='', help='Arguments to pass to the service executable when starting the service')
    group.add_argument('-pipe', action='store', help='Named pipe to read stdout from (e.g. "mypipe")')
    group.add_argument('-remote-binary-name', action='store', default='Jump.exe', help='Name of the binary once uploaded to the target (default: same as local file name)')
    group.add_argument('-share-path', action='store', metavar='share_path', default=None, help='Remote share and path where the service executable will be uploaded in the format <SHARE_NAME>\\path\\to\\file.exe (default: (default: searching for writable share)')
    group.add_argument('-create', action=argparse.BooleanOptionalAction, default=False, help='Create the service on the target system (default: False)')
    group.add_argument('-start', action=argparse.BooleanOptionalAction, default=False, help='Start the service after creation (default: False)')
    group.add_argument('-stop', action=argparse.BooleanOptionalAction, default=False, help='Stop and delete the service after execution (default: False)')
    group.add_argument('-delete', action=argparse.BooleanOptionalAction, default=False, help='Delete the service after stopping it (default: False)')
    group.add_argument('-cleanup', action=argparse.BooleanOptionalAction, default=False, help='Stop and delete the service (if exists) (default: False)')
    group.add_argument('-info', action=argparse.BooleanOptionalAction, default=False, help='Query and display service information (default: False)')
    group.add_argument('-change-info', action=argparse.BooleanOptionalAction, default=False, help='Change service information (description, display name) (default: False)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)
    
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())

    if sum([options.create, options.start, options.stop, options.delete, options.info, options.change_info, options.cleanup]) != 1:
        logging.critical('You can only choose one of -create, -start, -stop, -delete, -info, -change-info, or -cleanup options at a time.')
        sys.exit(1)

    domain, username, password, target = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = target
    
    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")
    
    if options.aesKey is not None:
        options.k = True
    
    # Implement the JUMP class later
    jump = JUMP(
        exeFile=options.service_exe,
        port=int(options.port),
        username=username,
        password=password,
        domain=domain,
        hashes=options.hashes,
        aesKey=options.aesKey,
        doKerberos=options.k,
        kdcHost=options.dc_ip,
        target=options.target_ip,
        serviceName=options.service_name,
        serviceDisplayName=options.service_display_name,
        serviceDescription=options.service_description,
        serviceArgs=options.service_args,
        remoteBinaryName=options.remote_binary_name,
        sharePath=options.share_path,
        pipeName=options.pipe
    )

    if options.create:
        jump.create_service(remoteName=target, remoteHost=options.target_ip)
    
    if options.start:
        jump.start_service(remoteName=target, remoteHost=options.target_ip)
    
    if options.delete:
        jump.delete_service(remoteName=target, remoteHost=options.target_ip)
    
    if options.stop:
        jump.stop_service(remoteName=target, remoteHost=options.target_ip)   
    
    if options.cleanup:
        jump.cleanup_service(remoteName=target, remoteHost=options.target_ip)

    if options.info:
        jump.print_service_info(remoteName=target, remoteHost=options.target_ip)
    
    if options.change_info:
        jump.change_service_info(remoteName=target, remoteHost=options.target_ip)
        

if __name__ == "__main__":
    main()
