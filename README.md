# gooroom-interpreters-lock

## Intro
- To control unauthorized execution of interpreters and script files e.g. Python and Perl
- Hooking sys_execve(), sys_execveat(), bprm_change_interp() in the Linux kernel (Referred to [ftrace-hook](https://github.com/ilammy/ftrace-hook))
- IMA-EVM or noexec mount option required

## Test environment
- Debian 9 (Stretch), Debian 10 (Buster), Debian 11 (Bullseye)
- Ubuntu 20.04 (Focal Fossa)

## Build and install
	$ sudo apt install build-essential linux-headers-$(uname -r) 
	$ ./build_run.sh
	$ ./build_debug.sh # only for debugging

## Details
- [OSSummit 2021 presentation slide](https://sched.co/lAVZ)

## Etc
### Enable/Disable via sysfs
	$ sudo /bin/bash -c 'echo "0" > /sys/fs/interp_lock/lock_state' # Disable
	$ sudo /bin/bash -c 'echo "1" > /sys/fs/interp_lock/lock_state' # Enable

### Auto-loading at booting
	$ sudo cp ./gooroom_interp_lock.ko /lib/modules/$(uname -r)/kernel/drivers/
	$ echo 'gooroom_interp_lock' | sudo tee -a /etc/modules
	$ sudo depmod

## Acknowledgments
This program has been developed for the security of the Gooroom platform which is an open-source project. This work was supported by Institute for Information & communications Technology Promotion (IITP) grant funded by the Korea government (MSIP) (No.R0236-15-1006, Open Source Software Promotion).
