import "pe"

rule apt_ZZ_MeteorExpress_wiper_broad 
{
	meta:
		desc = "Meteor wiper - broad hunting rule"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "07.23.2021"
		hash = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
	strings:
		$meteor1 = "Meteor is still alive." ascii wide
		$meteor2 = "Meteor has finished. This shouldn't be possible because of the is-alive loop." ascii wide
		$meteor3 = "Meteor has started." ascii wide

		$rtti1 = ".?AVBlackHoleException@@" ascii wide
		$rtti2 = ".?AVWiperException@@" ascii wide
		$rtti3 = ".?AVMiddleWiperException@@" ascii wide
		$rtti4 = ".?AVCMDException@@" ascii wide
		$rtti5 = ".?AVCouldNotFindNewWinlogonException@@" ascii wide
		$rtti6 = ".?AVLockScreenException@@" ascii wide
		$rtti7 = ".?AVScreenSaverException@@" ascii wide
		$rtti8 = ".?AVFailedToIsolateFromDomainWinapiException@@" ascii wide
		$rtti9 = ".?AVFailedToIsolateFromDomainWmiException@@" ascii wide
		$rtti10 = ".?AVSettingPasswordException@@" ascii wide
		$rtti11 = ".?AVPasswordChangerException@@" ascii wide
		$rtti12 = ".?AVEnumeratingUsersException@@" ascii wide
		$rtti13 = ".?AVProcessTerminationFailedException@@" ascii wide
		$rtti14 = ".?AVProcessNotTerminatedException@@" ascii wide
		$rtti15 = ".?AVFirstProcessWasNotFoundException@@" ascii wide
		$rtti16 = ".?AVProcessSnapshotCreationFailedException@@" ascii wide
		$rtti17 = ".?AVProcessTerminatorException@@" ascii wide
		$rtti18 = ".?AVOpenProcessFailedException@@" ascii wide
		$rtti19 = ".?AVFailedToLockException@@" ascii wide
		$rtti20 = ".?AVLockerException@@" ascii wide
		$rtti21 = ".?AVBCDException@@" ascii wide
		$rtti22 = ".?AVCouldNotCreateProcessException@@" ascii wide
		$rtti23 = ".?AVPipeNotCreatedCMDException@@" ascii wide

		$config_keys1 = "state_path" ascii wide fullword
		$config_keys2 = "log_encryption_key" ascii wide fullword
		$config_keys3 = "processes_to_kill" ascii wide fullword
		$config_keys4 = "process_termination_timeout" ascii wide fullword
		$config_keys5 = "log_server_port" ascii wide fullword
		$config_keys6 = "locker_background_image_jpg_path" ascii wide fullword
		$config_keys7 = "auto_logon_path" ascii wide fullword
		$config_keys8 = "locker_background_image_bmp_path" ascii wide fullword
		$config_keys9 = "state_encryption_key" ascii wide fullword
		$config_keys10 = "log_server_ip" ascii wide fullword
		$config_keys11 = "log_file_path" ascii wide fullword
		$config_keys12 = "paths_to_wipe" ascii wide fullword
		$config_keys13 = "wiping_stage_logger_interval" ascii wide fullword
		$config_keys14 = "locker_installer_path" ascii wide fullword
		$config_keys15 = "locker_exe_path" ascii wide fullword
		$config_keys16 = "locker_registry_settings_files" ascii wide fullword
		$config_keys17 = "locker_password_hash" ascii wide fullword
		$config_keys18 = "users_password" ascii wide fullword
		$config_keys19 = "cleanup_scheduled_task_name" ascii wide fullword
		$config_keys20 = "self_scheduled_task_name" ascii wide fullword
		$config_keys21 = "cleanup_script_path" ascii wide fullword
		$config_keys22 = "is_alive_loop_interval" ascii wide fullword		

		$failure1 = "failed to initialize configuration from file %s" ascii wide
		$failure2 = "Failed to find base-64 data size. Error code: %s." ascii wide
		$failure3 = "Failed to encode wide-character string as Base64. Error code: %s." ascii wide
		$failure4 = "Failed to generate password of length %s. Generating a default one." ascii wide
		$failure5 = "Failed creating scheduled task for system with name %s." ascii wide
		$failure6 = "Failed to add a new administrator: %s." ascii wide
		$failure7 = "Failed logging off session: %s" ascii wide
		$failure8 = "Failed creating scheduled task with name %s for user %s." ascii wide
		$failure9 = "Failed to wipe file %s" ascii wide
		$failure10 = "Failed to create thread. Error message: %s" ascii wide
		$failure11 = "failed to get configuration value with key %s" ascii wide
		$failure12 = "failed to parse the configuration from file %s" ascii wide
		$failure13 = "Failed to create handle. Error code %s" ascii wide
		$failure14 = "failed to write message to log file %s" ascii wide
		$failure15 = "Getting new winlogon session failed. Attempts: %s/%s" ascii wide
		$failure16 = "Failed creating processes snapshot, process name: %s, error code %s." ascii wide
		$failure17 = "Failed to query process info from snapshot. Process name: %s, error code: %s." ascii wide
		$failure18 = "Failed to add new user %s. Error code %s." ascii wide
		$failure19 = "Failed opening process, process name: %s, error code %s." ascii wide
		$failure20 = "Failed to open the access token of a process. Error code: %s" ascii wide
		$failure21 = "Failed to enumerate local WTS. The error code: %s" ascii wide
		$failure22 = "Failed to duplicate the access token of a process. Error code: %s" ascii wide
		$failure23 = "Failed to query the session id of a given token. Error code: %s." ascii wide
		$failure24 = "Failed to add user %s to group %s. Error code %s" ascii wide
		$failure25 = "Failed to set value for key %s. Error code: %s." ascii wide
		$failure26 = "Failed to retrieve subkey of HKEY_USER. index is %s. error code %s." ascii wide
		$failure27 = "Failed to disable rotating lock screen for user %s." ascii wide
		$failure28 = "Failed to isolate from domain using wmi. Error code: %s." ascii wide
		$failure29 = "Failed to isolate from domain using winapi. Error code %s" ascii wide
		$failure30 = "Failed while trying to wipe files: %s" ascii wide
		$failure31 = "Failed to change password for user %s. Error code %s." ascii wide
		$failure32 = "Failed to get network info. Error code %s" ascii wide
		$failure33 = "Failed to open process. Pid: %s, error code: %s" ascii wide
		$failure34 = "Failed to terminate process. Pid: %s, error code: %s" ascii wide
		$failure35 = "Failed to create a snapshot of the running processes. Error code: %s." ascii wide
		$failure36 = "Failed to delete locker lock screen, path %s" ascii wide
		$failure37 = "Failed to delete locker uninstaller from path %s" ascii wide
		$failure38 = "Failed to flush key %s: %s." ascii wide
		$failure39 = "Gfailed to parse json from file %s" ascii wide
		$failure40 = "failed to read from json file %s" ascii wide
		$failure41 = "Failed to wait for a mutex. the return value was: %s." ascii wide
		$failure42 = "Waiting for process failed. Error: %s" ascii wide
		$failure43 = "Failed to open key %s, with error %s." ascii wide
		$failure44 = "Failed to query information of hkey %s." ascii wide
		$failure45 = "Failed to get value for key %s. Failed with error code %s" ascii wide
		$failure46 = "Failed disabling wow 64 redirection mechanism. Error code %s" ascii wide
		$failure47 = "Failed getting  %s module. Error code %s" ascii wide
		$failure48 = "Failed retrieving method address, method name: %s. Error code %s" ascii wide
		$failure49 = "Failed to adjust access token privileges." ascii wide
		$failure50 = "Failed to retrieve LUID for a privilege name in local system." ascii wide
		$failure51 = "Failed to initiate reboot." ascii wide
		$failure52 = "Failed to retrieve process token." ascii wide
		$failure53 = "Failed to change lock screen in Windows XP." ascii wide
		$failure54 = "Failed to register auto logon" ascii wide
		$failure55 = "Failed to change lock screen in Windows 7." ascii wide
		$failure56 = "Failed to change lock screen in Windows 10." ascii wide
		$failure57 = "PLocker failed" ascii wide
		$failure58 = "Failed to isolate from domain using wmi because command couldn't run" ascii wide
		$failure59 = "Failed to parse domain and username data." ascii wide
		$failure60 = "Failed to run the locker" ascii wide
		$failure61 = "Failed to find default browser" ascii wide
		$failure62 = "Failed to install locker" ascii wide
		$failure63 = "Failed to terminate the locker process." ascii wide
		$failure64 = "Failed to import locker settings" ascii wide
		$failure65 = "Failed to set locker settings." ascii wide
		$failure66 = "Failed to lock" ascii wide
		$failure67 = "Failed to create mutex." ascii wide
		$failure68 = "Supplier failed while iterating filter functions that check if a file is valid." ascii wide
		$failure69 = "Supplier failed while filtering an existing target." ascii wide
		$failure70 = "Supplier failed while filtering a potential target." ascii wide
		$failure72 = "Wiper operation failed." ascii wide
		$failure73 = "Screen saver disable failed." ascii wide
		$failure74 = "Failed to delete boot configuration" ascii wide
		$failure75 = "Failed to change lock screen" ascii wide
		$failure76 = "Failed to kill all winlogon processes" ascii wide
		$failure77 = "Process terminator failed" ascii wide
		$failure78 = "Failed to change the passwords of all users" ascii wide
		$failure79 = "Failed to run the locker thread" ascii wide
		$failure80 = "Generating random password failed" ascii wide
		$failure81 = "Locker installation failed" ascii wide
		$failure82 = "Failed to set auto logon." ascii wide
		$failure83 = "Failed to initialize interval logger. Using a dummy logger instead." ascii wide
		$failure84 = "Failed disabling the first logon privacy settings user approval." ascii wide
		$failure85 = "Failed disabling the first logon animation." ascii wide
		$failure86 = "Failed to isolate from domain" ascii wide
		$failure87 = "Failed to get the new token of winlogon." ascii wide
		$failure88 = "Failed adding new admin user." ascii wide
		$failure89 = "Failed changing settings for the created new user." ascii wide
		$failure90 = "Failed disabling recovery mode." ascii wide
		$failure91 = "Failed to log off all sessions" ascii wide
		$failure92 = "Failed to delete shadowcopies." ascii wide
		$failure93 = "Failed setting boot policy to ignore all errors." ascii wide
		$failure94 = "Failed logging off all local sessions, except winlogon." ascii wide

		$log1 = "Succeeded loggingoff session: %s" ascii wide fullword
		$log2 = "Logging off all local sessions, except winlogon." ascii wide fullword
		$log3 = "Logging off all sessions." ascii wide fullword
		$log4 = "Logging off users on Windows version 8 or above" ascii wide fullword
		$log5 = "Logging off users in Windows 7" ascii wide fullword
		$log6 = "Logging off users in Windows XP" ascii wide fullword
		$log7 = "End interval logger. Resuming writing every log." ascii wide fullword
		$log8 = "Exiting main function because of some error" ascii wide fullword

		$lockMyPC1 = "C:\\Program Files\\Lock My PC 4\\unins000.exe" ascii wide fullword
		$lockMyPC2 = "SOFTWARE\\FSPro Labs\\Lock My PC 4" ascii wide fullword
		$lockMyPC3 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen2.jpg" ascii wide fullword
		$lockMyPC4 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen1.jpg" ascii wide fullword
		$lockMyPC5 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen4.jpg" ascii wide fullword
		$lockMyPC6 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen3.jpg" ascii wide fullword
		$lockMyPC7 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen6_r.gif" ascii wide fullword
		$lockMyPC8 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen5_b.gif" ascii wide fullword

		$bcd1 = "bcdedit.exe /set {default} recoveryenabled no" ascii wide fullword
		$bcd2 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii wide fullword
		$bcd3 = "sCould not delete BCD entry. Identifier: %s" ascii wide fullword
		$bcd4 = "Could not delete all BCD entries." ascii wide fullword
		$bcd5 = "Finished deleting BCD entries." ascii wide fullword
		$bcd6 = "Reached maximum number of BCD entry deletion attempts." ascii wide fullword
		$bcd7 = "Could not get BCD entries." ascii wide fullword
		$bcd8 = "bcd00000000\\objects" ascii wide fullword

		$password1 = "Changing passwords of all users to %s" ascii wide fullword
		$password2 = "Succeeded adding new user %s with password %s." ascii wide fullword
		$password3 = "Changed the password of local user %s to %s." ascii wide fullword
		$password4 = "The password's length is smaller than the complex prefix. Returning a fixed prefix." ascii wide fullword

		$boot1 = "default=multi(0)disk(10000000)rdisk(0)partition(1000000)\\WINDOWS" ascii wide
		$boot2 = "multi(0)disk(10000000)rdisk(0)partition(1000000)\\WINDOWS=\"Microsoft Windows XP Professional\" /noexecute=optin /fastdetect" ascii wide

		$success1 = "Succeeded setting auto logon for %s." ascii wide fullword
		$success2 = "Succeeded creating scheduled task for system with name %s." ascii wide fullword
		$success3 = "Succeeded creating scheduled task with name %s for user %s." ascii wide fullword
		$success4 = "Unsuccessful exit code returned from cmd: %s. Exit code: %s." ascii wide fullword
		$success5 = "Succeeded adding new user %s to group %s." ascii wide fullword
		$success6 = "Successfully disabled rotating lock screen saver of user %s." ascii wide fullword
		$success7 = "Successfully removed %s from lock screen directory." ascii wide fullword
		$success8 = "Terminated process successfully. process name: %s, pid: %s" ascii wide fullword
		$success9 = "Process created successfully. Executed command: %s." ascii wide fullword
		$success10 = "Success restarting machine using cmd." ascii wide fullword
		$success11 = "Successfully changed lock screen image in Windows 7" ascii wide fullword
		$success12 = "Successfully changed lock screen image in Windows 10" ascii wide fullword
		$success13 = "Successfully changed lock screen image in Windows XP" ascii wide fullword
		$success14 = "Unjoining domain using WMIC finished successfully" ascii wide fullword
		$success15 = "Unjoining domain using WINAPI finished successfully" ascii wide fullword
		$success16 = "Succeeded disabling the first logon animation." ascii wide fullword
		$success17 = "Succeeded disabling the first logon privacy settings user approval." ascii wide fullword
		$success18 = "Boot configuration deleted successfully" ascii wide fullword
		$success19 = "Screen saver disabled successfully." ascii wide fullword
		$success20 = "Succeeded setting boot policy to ignore all errors." ascii wide fullword
		$success21 = "Succeeded disabling recovery mode." ascii wide fullword
		$success22 = "Successfully logged off all local sessions, except winlogon." ascii wide fullword
		$success23 = "Succeeded deleting shadowcopies." ascii wide fullword

		$locker1 = "Installing the locker from path %s" ascii wide fullword
		$locker2 = "Removing locker uninstaller from path %s" ascii wide fullword
		$locker3 = "Started changing lock screen image in Windows 7." ascii wide fullword
		$locker4 = "Started changing lock screen image in Windows XP." ascii wide fullword
		$locker5 = "Could not remove lock screen cache directory _P." ascii wide fullword
		$locker6 = "Started changing lock screen image in Windows 10." ascii wide fullword
		$locker7 = "Could not remove lock screen cache directory _Z." ascii wide fullword
		$locker8 = "eUpdating locker settings" ascii wide fullword
		$locker9 = "The locker is not installed" ascii wide fullword
		$locker10 = "Running locker thread" ascii wide fullword

		$attempt1 = "attempted to access encrypted file in offset %s, but it only supports offset 0" ascii wide
		$attempt2 = "Attempting to restart machine using cmd in %s seconds" ascii wide
		$attempt3 = "Attempting to restart machine using winapi in %s seconds" ascii wide
		$attempt4 = "Attempted to restart asynchronously using cmd." ascii wide
		$attempt5 = "Attempted to restart asynchronously using WINAPI." ascii wide
		$attempt6 = "Restart attempted using cmd, while another restart is already initiated." ascii wide
		$attempt7 = "Reached maximal attempts of getting a new winlogon token" ascii wide

		$process1 = "Process %s was not found." ascii wide fullword
		$process2 = "Could not find snapshot's first process. Error code: %s" ascii wide fullword
		$process3 = "Process %s with pid %s was not terminated." ascii wide fullword
		$process4 = "Process termination wait timed out. Error code: %s" ascii wide fullword
		$process5 = "Could not get process exit code. Error code: %s." ascii wide fullword
		$process6 = "Process exit code is %s." ascii wide fullword
		$process7 = "Could not create process. Command: %s, error code: %s." ascii wide fullword
		$process8 = "Could not create impersonated process. Command: %s, error code: %s." ascii wide fullword
		$process9 = "Encountered an error while terminating process with fatal priority. continuing" ascii wide fullword
		$process10 = "Process has finished." ascii wide fullword
		$process11 = "Waiting for new winlogon process" ascii wide fullword
		$process12 = "Killing all winlogon processes" ascii wide fullword
		
		$command1 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant System:(OI)(CI)F /T" ascii wide
		$command2 = "takeown.exe /F \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /R /A /D Y" ascii wide
		$command3 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant Administrators:(OI)(CI)F /T" ascii wide
		$command4 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant System:(OI)(CI)F /T" ascii wide
		$command5 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\\S-1-5-18\\ReadOnly\" /reset /T" ascii wide
		$command6 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant Administrators:(OI)(CI)F /T" ascii wide
		$command7 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /reset /T" ascii wide
		$command8 = "wmic computersystem where name=\"%computername%\" call unjoindomainorworkgroup" ascii wide
		$command9 = "vssadmin.exe delete shadows /all /quiet" ascii wide
		$command10 = "shutdown.exe /r /f /t " ascii wide
		$command11 = "wbem\\wmic.exe shadowcopy delete" ascii wide
		$command12 = "takeown.exe /F \"C:\\Windows\\Web\\Screen\" /R /A /D Y" ascii wide

		$formatStr1 = "File %s is not readable." ascii wide fullword
		$formatStr2 = "File %s is not writable." ascii wide fullword
		$formatStr3 = "Could not open file %s. error message: %s" ascii wide fullword
		$formatStr4 = "Could not write to file %s. error message: %s" ascii wide fullword
		$formatStr5 = "tCould not tell file pointer location on file %s." ascii wide fullword
		$formatStr6 = "Could not set file pointer location on file %s to offset %s." ascii wide fullword
		$formatStr7 = "Could not read from file %s. error message: %s" ascii wide fullword
		$formatStr8 = "File %s does not exist" ascii wide fullword
		$formatStr9 = "Skipping %s logs. Writing log number %s: " ascii wide fullword
		$formatStr10 = "Start interval logger. Writing logs with an interval of %s logs." ascii wide fullword
		$formatStr11 = "The log message is too big: %s/%s characters." ascii wide fullword
		$formatStr13 = "Found local user: %s." ascii wide fullword
		$formatStr14 = "Filesystem failure: %s" ascii wide fullword
		$formatStr15 = "Couldn't wipe file %s." ascii wide fullword
		$formatStr16 = "Finished wiping file %s with %s." ascii wide fullword
		$formatStr17 = "Started wiping file %s with %s." ascii wide fullword
		$formatStr18 = "Failure while enumerating local users. Error code: %s." ascii wide fullword
		$formatStr19 = "The browser %s is not supported" ascii wide fullword
		$formatStr20 = ".json array size is %s, but should have been %s" ascii wide fullword
		$formatStr21 = "ejson uint value is not in range %s to %s." ascii wide fullword
		$formatStr22 = "The path %s does not exist." ascii wide fullword
		$formatStr23 = "A path in %s could not be accessed. Continuing..." ascii wide fullword
		$formatStr24 = "The directory path %s could not be iterated." ascii wide fullword
		$formatStr25 = "Caught std::filesystem::filesystem_error: %s" ascii wide fullword
		$formatStr26 = "Line %d, Column %d" ascii wide fullword
		$formatStr27 = "Error from reader: %s" ascii wide fullword
		$formatStr28 = "%s %s HTTP/1.1" ascii wide fullword

		$settings1 = "unknown_hostname" ascii wide fullword
		$settings2 = "unknown_mac" ascii wide fullword
		$settings3 = "copy_file" ascii wide fullword
		$settings4 = "create_directories" ascii wide fullword

		$couldnt1 = "Could not change background image." ascii wide fullword
		$couldnt2 = "Could not create stdout pipe." ascii wide fullword
		$couldnt3 = "Could not set handle information for pipe." ascii wide fullword
		$couldnt4 = "Could not hide current console." ascii wide fullword
		$couldnt5 = "Could not get the window handle used by the console." ascii wide fullword

		$random1 = "C:\\Windows\\Sysnative\\" ascii wide fullword
		$random2 = "C:\\Windows\\system32\\" ascii wide fullword
		$random3 = "MESSAGE_IN_QUEUE" ascii wide fullword
		$random4 = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36" ascii wide fullword
		$random5 = "cpp-httplib/0.2" ascii wide fullword
	
	condition:
		uint16(0) == 0x5a4d
		and
		(
			any of ($meteor*)
			or
			5 of ($rtti*)
			or
			5 of ($config_keys*)
			or
			10 of ($failure*)
			or
			2 of ($log*)
			or
			all of ($lockMyPC*)
			or
			4 of ($bcd*)
			or
			2 of ($password*)
			or
			any of ($boot*)
			or
			3 of ($success*)
			or
			3 of ($locker*)
			or
			2 of ($attempt*)
			or
			3 of ($process*)
			or
			3 of ($command*)
			or
			10 of ($formatStr*)
			or
			all of ($settings*)
			or
			all of ($couldnt*)
			or
			all of ($random*)
		)
}

rule apt_ZZ_MeteorExpress_locker
{
	meta:
		desc = "MeteorExpress ScreenLocker"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "07.21.2021"
		hash = "074bcc51b77d8e35b96ed444dc479b2878bf61bf7b07e4d7bd4cf136cc3c0dce"
	strings:
		$a1 = "WindowClass" ascii wide fullword
		$a2 = "C:\\temp\\mscap.bmp" ascii wide
		$a3 = ".?AVCreateWindowFailed@exceptions@@" ascii wide
		$a4 = ".00cfg" ascii wide fullword
	condition:
		uint16(0) == 0x5a4d
		and
		all of them
}
