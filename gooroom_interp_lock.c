/*
 * Gooroom Interpreter Lock based on ftrace feature
 *
 * Copyright (c) 2020 ultract
 */

#include "ftrace_hook.h"
#include "sysfs_attr.h"
#include <linux/file.h>
#include <linux/glob.h>


#define EXECVE 0
#define EXECVEAT 1

/**
 * get_user_arg_ptr - get argument pointers from user
 * @argv: argv pointer from user
 * @nr: index value of argv	
 */
static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/**
 * count - get a argc of execve syscall
 * @argv: argv of execve syscall
 * @max: maximum value of a argc
 */
static int count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

/**
 * realpath - Get the realpath from a relative path, a symbolic link, ...
 * @pathname: a path name for finding out real path
 */
static char *realpath(char *pathname)
{
	int err;
	struct path path;
	char *path_buf, *tmp_path, *ret_path;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!path_buf))
		return ERR_PTR(-ENOMEM);

    memset(path_buf, 0, PATH_MAX);
	err = kern_path(pathname, LOOKUP_FOLLOW, &path);

	if (unlikely(err < 0)) {
		pr_debug("realpath() kern_path error : %d, pathname : %s, pid: %d\n", 
				 err, pathname, current->pid);
		kfree(path_buf);
		return ERR_PTR(err);
	}
	tmp_path = d_path(&path, path_buf, PATH_MAX);
	pr_debug("realpath() tmp_path:%s(%lx)\n", tmp_path, (long unsigned int)tmp_path);
	ret_path = kstrdup(tmp_path, GFP_KERNEL);
	kfree(path_buf);

	if (unlikely(!ret_path))
		return ERR_PTR(-ENOMEM);

	return ret_path;
}

/**
 * fd_path - Get the file path by the file descriptor
 * @fd: the file descriptor
 */
static char *fd_path(unsigned int fd)
{
	struct file *file;
	char *path_buf, *tmp_path, *ret_path;

	/* Get struct file * */
	file = fget((unsigned int) fd);
	if (!file) {
		pr_debug("fd_path(), fget() failed\n");
		return NULL;
	}

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	memset(path_buf, 0, PATH_MAX);

	/* Get the path by the variable in struct path */
	tmp_path = d_path(&(file->f_path), path_buf, PATH_MAX);
	pr_debug("fd_path(), tmp_path:%s(%lx)\n", tmp_path, (long unsigned int)tmp_path);
	if (IS_ERR(tmp_path)) {
		pr_debug("fd_path(), d_path() error!\n");
		kfree(path_buf);
		return NULL;
	}
	ret_path = kstrdup(tmp_path, GFP_KERNEL);
	kfree(path_buf);
	return ret_path;
}


/**
 * Path filters - writable directories for normal users
 * 
 */
static char *path_filter_1 = "/home/";
static char *path_filter_2 = "/tmp/";
static char *path_filter_3 = "/run/";
static char *path_filter_4 = "/var/tmp";
static char *path_filter_5 = "/dev/shm/";
static char *path_filter_6 = "/dev/mqueue/";
static char *path_filter_7 = "/media/";

/**
 * Interpreter filters - interpreter files
 *
 */
static char *interp_filter_1 = "/usr/bin/python";
static char *interp_filter_2 = "/usr/bin/perl"; 
static char *interp_filter_3 = "/usr/lib/python2.7/pdb.py"; 
static char *interp_filter_4 = "/usr/lib/python3.7/pdb.py"; 
/*
static char *interp_filter_3 = "/bin/bash"; 
static char *interp_filter_4 = "/bin/dash"; 
static char *interp_filter_5 = "/usr/lib/klibc/bin/sh";
*/

/**
 * Other filters
 *
 * python_comm_opt:	python inline command option
 * perl_comm_opt:	perl inline command option
 * memfd: 		a memory-mapped file by memfd_create
 * lib_loader:		dynamic linker name for an ELF binary
 * shell_end_opt:   The shell's delimiter to indicate the end of execution options
 */
static char python_comm_opt = 'c';
static char python_imode_opt = 'i';
static char python_module_opt = 'm';
static char perl_comm_opt = 'e';
static char perl_comm_opt_2 = 'E';
static char perl_dbg_opt = 'd';
static char *memfd = "/memfd:";
static char *python_envp_1 = "PYTHONINSPECT=";
static char *python_envp_2 = "PYTHONPATH=";
static char *dash_opt = "-";
static char *shell_end_opt = "--";
/*
static char bash_comm_opt = "c";
*/

/* /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 */
//static char *lib_loader = "ld-linux-x86-64.so.2";
//static char *lib_loader = "/lib/x86_64-linux-gnu/ld-2.28.so";		/* Gooroom 1.x */
static char *lib_loader = "/usr/lib/x86_64-linux-gnu/ld*.so";	/* Gooroom 2.x */



/*
static int interp_filter(const char *target)
{
	if(!strncmp(target, interp_filter_1, strlen(interp_filter_1)))
		return 1;
	else if (!strncmp(target, interp_filter_2, strlen(interp_filter_2)))
		return 2;
	else if (!strncmp(target, interp_filter_3, strlen(interp_filter_3)))
		return 3;
	else if (!strncmp(target, interp_filter_4, strlen(interp_filter_4)))
		return 4;
	else if (!strncmp(target, interp_filter_5, strlen(interp_filter_5)))
		return 5;

	return 0;
}
*/

/**
 *	interp_filter
 *
 *  filtering all interpreter paths by strstr()
 *	E.g./usr/bin/python, /var/overlay2/docker/xxx...xxx/usr/bin/python
 */
static int interp_filter(const char *target)
{
	if(strstr(target, interp_filter_1))
		return 1;
	else if (strstr(target, interp_filter_2))
		return 2;
	else if (strstr(target, interp_filter_3))
		return 3;
	else if (strstr(target, interp_filter_4))
		return 4;
/*	else if (!strstr(target, interp_filter_5))
		return 5;
*/
	return 0;
}

static int path_filter(const char *path)
{

	if (!strncmp(path, path_filter_1, strlen(path_filter_1)))
		return 1;
	else if (!strncmp(path, path_filter_2, strlen(path_filter_2)))
		return 2;
	else if (!strncmp(path, path_filter_3, strlen(path_filter_3)))
		return 3;
	else if (!strncmp(path, path_filter_4, strlen(path_filter_4)))
		return 4;
	else if (!strncmp(path, path_filter_5, strlen(path_filter_5)))
		return 5;
	else if (!strncmp(path, path_filter_6, strlen(path_filter_6)))
		return 6;
	else if (!strncmp(path, path_filter_7, strlen(path_filter_7)))
		return 7;

	return 0;
}

static DEFINE_MUTEX(execve_lock);

/**
 * envp_filter
 * Look into environment variables, e.g. PYTHONINSPECT
 * 
 */

/* Index of Auxiliary Vector for Environment Variables */
#define AUXV_ENVP_IDX 41

static int envp_filter(void)
//static int envp_filter(const char __user *const __user *envp)
{
	int i, envc;
	char *tmp_envp, *envp_val;
	ssize_t err;
	int pret;

	//struct user_arg_ptr __envp = { .ptr.native = envp_dup };

	/* Getting the address of envp from Auxiliary Vector */
	struct user_arg_ptr __envp = { .ptr.native = (const char __user * const __user *)current->mm->saved_auxv[AUXV_ENVP_IDX]};
	envc = count(__envp, MAX_ARG_STRINGS);

/*
	pr_debug("envp_filter, envc=%d, envp_dup(%lx)=%lx __envp.ptr.native=%lx\n", 
			  envc, (unsigned long)&envp_dup, (unsigned long)envp_dup, (unsigned long)__envp.ptr.native);
*/

	/* envp pointer error */
	if (envc == -EFAULT) {
		pr_debug("envp variable pointer error");
		//dump_stack(); // Print backtrace of stack
		return 1;
		//return 0;
	}

	for (i = 0; i < envc; i++){
		const char __user *p = get_user_arg_ptr(__envp, i);
		//pr_debug("get_user_arg_ptr = %lx\n", (unsigned long)p);
		tmp_envp = strndup_user(p, MAX_ARG_STRLEN);
		
		if (IS_ERR(tmp_envp)) {
			err = PTR_ERR(tmp_envp);
			pr_debug("strndup_user for envp, error = %ld\n", err);
			return 1;
		}
		//pr_info("%s(%d))\n", tmp_envp, strnlen(tmp_envp, MAX_ARG_STRLEN));
		//pr_debug("envp[%d] :  %s\n", i, tmp_envp);

		if (!strncmp(tmp_envp, python_envp_1, strlen(python_envp_1))) {
			pr_warning("envp variables restricted: %s\n", tmp_envp);
			kfree(tmp_envp);
			return 1;

		} else if (!strncmp(tmp_envp, python_envp_2, strlen(python_envp_2))) {
			/* Get a path name from the envp */
			envp_val = tmp_envp + (char)strlen(python_envp_2);
			//pr_debug("tmp_envp: %s\ntmp_path: %s", tmp_envp, tmp_path);
			if ((pret = path_filter(envp_val))) {
				pr_warning("envp variables restricted: %s, %d\n", tmp_envp, pret);
				kfree(tmp_envp);
				return 1;
			}
		}
		kfree(tmp_envp);
	}
	return 0;
}


/**
 * fh_sys_execve_at_common - execve and execveat hook main function 
 * @fd: a file descriptor of execveat
 * @filename:	a filename pointer of execve or execveat
 * @argv:	an argv pointer of execve or execveat 
 * @envp:	an envp pointer of execve or execveat
 * @flags: flags execveat
 */

static int asmlinkage fh_sys_execve_at_common(int fd,
					const char __user *filename,
					const char __user *const __user *argv,
					const char __user *const __user *envp,
					int flags,
					int chk_syscall)
{
	int i, argc;
	char *execve_fname, *tmp_fname;
	char *tmp_argv, *argv_path;
	kuid_t ck_euid;
	ssize_t err;
	int iret, pret, eret;
	char *dir_path, *tmp_path;
	char *tmp_buf;
	

	/* Get argv pointer address in usermode */
	struct user_arg_ptr __argv = { .ptr.native = argv };
	
	/* Get envp pointer address in usermode */
	//struct user_arg_ptr __envp = { .ptr.native = envp };
	//__envp.ptr.native = envp;

	/* Putting the envp address to Auxiliary Vector */
	current->mm->saved_auxv[AUXV_ENVP_IDX] = (unsigned long)envp;	

	/* Check lock_state */
	if (lock_state != true)
		return 0;
	
	/* Check user process euid */
	ck_euid.val = 1000;
	if (uid_lt(get_current_cred()->euid, ck_euid))
		return 0;

	/* Distinguish execve() and execveat() */
	if ((chk_syscall == EXECVEAT) && (fd >= 0)) {
		/* Get filename of execveat */
		tmp_path = strndup_user(filename, PATH_MAX);
		if (IS_ERR(tmp_path)) {
			err = PTR_ERR(tmp_path);
			pr_debug("strndup_user for execveat filename, error = %ld\n", err);
			return 0;
		}
		pr_debug("execveat() tmp_path: %s\n", tmp_path);

		/* Get the directory path by the fd  */
		dir_path = fd_path(fd);

		if (!dir_path) {
			pr_debug("fd_path() no path return\n");
			tmp_fname = tmp_path;
		} else {
			tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
			memset(tmp_buf, 0, PATH_MAX);
			strlcat(tmp_buf, dir_path, PATH_MAX);
			kfree(dir_path);

			if ((tmp_path[0] != '/') && (strlen(tmp_path) !=0 ))
				strlcat(tmp_buf, "/", PATH_MAX);

			strlcat(tmp_buf, tmp_path, PATH_MAX);
			tmp_fname = tmp_buf;
		}
		pr_debug("execveat() tmp_fname: %s\n", tmp_fname);

	} else { 

		tmp_fname = strndup_user(filename, PATH_MAX);
		if (IS_ERR(tmp_fname)) {
			err = PTR_ERR(tmp_fname);
			pr_debug("strndup_user for execve filename, error = %ld\n", err);
			return 0;
		}
	}

	/* Get a realpath the execve's filename */
	execve_fname = realpath(tmp_fname);
	if (IS_ERR(execve_fname)) {
		pr_debug("execve filename via realpath() error: %ld\n", PTR_ERR(execve_fname));
		kfree(tmp_fname);
		err = PTR_ERR(execve_fname);
		return err == -ENOMEM ? err : 0;
	}
	pr_debug("execve_fname: %s", execve_fname);
	kfree(tmp_fname);

	/* Check out dynamic linker (ELF interpreter) */
	if (glob_match(execve_fname, lib_loader)) {
		pr_warning("Execution via dynamic linker (ld-2.28.so)\n");

		/* Get argc from user */
		argc = count(__argv, MAX_ARG_STRINGS);

		/* Only dynimic linker execution */
		if (argc == 1){
			kfree(execve_fname);
			return 0;
		}
		
		/* Search for argv[1], argv[2], ..., argv[n] */
		for (i = 1; i < argc; i++){
			const char __user *p = get_user_arg_ptr(__argv, i);
			tmp_argv = strndup_user(p, PATH_MAX);
			
			/* Handle strndup_user error */
			if (IS_ERR(tmp_argv)) {
				err = PTR_ERR(tmp_argv);
				pr_debug("strndup_user for argv, error = %ld\n", err);
				kfree(execve_fname);
				return 0;
			}
			
			argv_path = realpath(tmp_argv);
			if (IS_ERR(argv_path)) {
				pr_debug("execve filename via realpath() error \n");
				kfree(tmp_argv);
				err = PTR_ERR(argv_path);
				return err == -ENOMEM ? err : 0;

			} else if ((iret = interp_filter(argv_path))) {
				pr_warning("Interpreter executed via dynamic linker : %s, pid : %d\n", argv_path, current->cred->euid.val);
				kfree(argv_path);
				kfree(tmp_argv);
				kfree(execve_fname);
				return -EPERM;
			}
			kfree(argv_path);
			kfree(tmp_argv);
		}
	}

	/* Check out memfd file (memfd_create) */
	if (!strncmp(execve_fname, memfd, strlen(memfd))){
 		/* Check the dentry's d_iname of memfd */
/*		struct fs_struct *tmp_fs = current->fs;
		struct path tmp_path= tmp_fs->root;
		struct vfsmount *tmp_vfsmnt = tmp_path.mnt;
		struct dentry *tmp_dentry = tmp_vfsmnt->mnt_root;
*/
		pr_warning("Unusual case : %s\n", execve_fname);
//		pr_debug("%s\n", tmp_dentry->d_iname);

		kfree(execve_fname);
		return -EPERM;
	}

	/* 
 	 * Check interpreter execution
	 * by execve arguments : filename and argv[n]
	 */
	if ((iret = interp_filter(execve_fname))) {

		/* Check the environment variables */
		eret = envp_filter();
		if((eret != 0)) {
			pr_debug("execve envp_filter()=%d\n", eret);
			kfree(execve_fname);
			return -EPERM;
		}

		/* Get argc from user */
		argc = count(__argv, MAX_ARG_STRINGS);
		pr_debug("Interpreter name : %s, pid : %d, argc: %d\n", execve_fname, current->pid, argc);
	
		/* Only interpreter execution by execve */
		if (argc <= 1) {
			pr_warning("Single interpreter execution blocked\n");
			kfree(execve_fname);
			return -EPERM;
		}

		/* Check argv[1], argv[2], ..., argv[n] */
		for (i = 1; i < argc; i++) {
			const char __user *p = get_user_arg_ptr(__argv, i);
			tmp_argv = strndup_user(p, PATH_MAX);
	
			/* Handle strndup_user error */
			if (IS_ERR(tmp_argv)) {
				err = PTR_ERR(tmp_argv);
				pr_debug("strndup_user for argv, error = %ld\n", err);
				kfree(execve_fname);
				return 0;
			}
			pr_debug("tmp_argv: %s, argc: %d\n", tmp_argv, argc);

			/*
			 *	Check the execution arguments
			 *
			 * The dash option of bash */
			if (!strcmp(tmp_argv, dash_opt)) {
				pr_warning("Single interpreter execution with '-' blocked\n");
				kfree(execve_fname);
				kfree(tmp_argv);
				return -EPERM;

			/* The shell's delimeter of the end of options */
			} else if (!strcmp(tmp_argv, shell_end_opt) && argc == 2) {
				pr_warning("Single interpreter execution with '--' blocked\n");
				kfree(execve_fname);
				kfree(tmp_argv);
				return -EPERM;

			/* Interpreter command line option */
			} else if (*tmp_argv == '-' && *(tmp_argv+1) != '\0') {
				if (strchr(tmp_argv, python_comm_opt) || strchr(tmp_argv, python_imode_opt) ||
					strchr(tmp_argv, python_module_opt) || strchr(tmp_argv, perl_comm_opt) ||
					strchr(tmp_argv, perl_comm_opt_2) || strchr(tmp_argv, perl_dbg_opt)){
						
					pr_warning("Interpreter command option blocked (%s)\n", tmp_argv);
					kfree(execve_fname);
					kfree(tmp_argv);
					return -EPERM;
				}
			}
			
			/* Get the realpath of argv[i] */
			argv_path = realpath(tmp_argv);
			if (IS_ERR(argv_path)) {
				pr_debug("argument path via realpath() error \n");
				kfree(tmp_argv);
				kfree(execve_fname);
				err = PTR_ERR(argv_path);
				return err == -ENOMEM ? err : 0;

			} else {

				pr_debug("execve_at_common() argv_path: %s\n", argv_path);
				kfree(tmp_argv);

				/* Check out memfd file (memfd_create) */
				if (!strncmp(argv_path, memfd, strlen(memfd))){
					pr_warning("execve_at_common() Unusual case : %s\n", argv_path);
					kfree(argv_path);
					kfree(execve_fname);
					return -EPERM;
				}

				if((pret = path_filter(argv_path))) {					
					pr_warning("Unauthorized script execution blocked : %s, %d\n", argv_path, pret);
					kfree(argv_path);
					kfree(execve_fname);
					return -EPERM;
				}
				kfree(argv_path);
			}
		}
	}
	kfree(execve_fname);
	return 0;
}



#ifdef PTREGS_SYSCALL_STUBS

/* execve */
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;

	/* Assign arguments from pt_regs */
	const char __user *filename = (void*) regs->di;
	const char __user *const __user *argv = (void*) regs->si;
	const char __user *const __user *envp = (void*) regs->dx;

	ret = mutex_lock_killable(&execve_lock);
	if (ret)
		return ret;

	ret = fh_sys_execve_at_common(-1, filename, argv, envp, -1, 0);

	if (ret != -EPERM) 
		/* EPERM->1, include/uapi/asm-generic/errno-base.h */
		ret = real_sys_execve(regs);

	mutex_unlock(&execve_lock);
	return ret;
}

/* execveat */
static asmlinkage long(*real_sys_execveat)(struct pt_regs *regs);

static asmlinkage long fh_sys_execveat(struct pt_regs *regs)
{
	long ret;

	/* Assign arguments from pt_regs */
	const int fd = (int) regs->di;
	const char __user *filename = (void*) regs->si;
	const char __user *const __user *argv = (void*) regs->dx;
	const char __user *const __user *envp = (void*) regs->r10;
	const int flags = (int) regs->r8;

	ret = mutex_lock_killable(&execve_lock);
	if (ret)
		return ret;

	ret = fh_sys_execve_at_common(fd, filename, argv, envp, flags, 1);

	if (ret != -EPERM)
		/* EPERM->1 */
		ret = real_sys_execveat(regs);

	mutex_unlock(&execve_lock);
	return ret;
}

#else

static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;

	//ret = fh_sys_execve_hook(filename, argv, envp);
	ret = fh_sys_execve_at_common(-1, filename, argv, envp, -1, 0);

	if (ret != -EPERM)
		ret = real_sys_execve(filename, argv, envp);

	return ret;
}

/* execveat */
static asmlinkage long(*real_sys_execveat)(int fd,
		const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp,
		int flags);

static asmlinkage long fh_sys_execveat(int fd,
		const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp,
		int flags);
{
	long ret;
	
	//ret = fh_sys_execveat_hook(fd, filename, argv, envp, flags);
	ret = fh_sys_execve_at_common(fd, filename, argv, envp, flags, 1);

	if (reg != -EPERM)
		/* EPERM->1 */
		ret = real_sys_execveat(regs);

	return ret;
}

#endif


/**
 * fh_bprm_change_interp - hooking bprm_change_interp
 * Handling a script file(#!,shebang) execution 
 * E.g. $ ./test.py or ./test.pl
 *
 */

static asmlinkage int (*real_bprm_change_interp)(char *interp, struct linux_binprm *bprm);

static asmlinkage int fh_bprm_change_interp(char *interp, struct linux_binprm *bprm)
{
	int ret;
	char *real_fname, *real_interp;
	kuid_t ck_euid;
	int iret, pret, eret;

	/* Refer to create_aout_tables() in fs/binfmt_aout.c */
	//const char __user *const __user *envp;
	
	/* Variables for printing auxiliary array */
	/*
	ssize_t err;
	char tmp[1024];
	int i;
	*/

	/* Check lock state */
	if (lock_state != true)
		goto pass;

	/* Check if process euid < 1000 */
	ck_euid.val = 1000;
	if (uid_lt(get_current_cred()->euid, ck_euid))
		goto pass;

	/* Check interp (absolute path) */
	real_interp = realpath(interp);
	if (IS_ERR(real_interp)) {
		pr_debug("interp realpath() error\n");
		ret = PTR_ERR(real_interp);
		if (ret == -ENOMEM)
			return ret;
		goto pass;
	}

	if ((iret = interp_filter(real_interp))) {
	
		/* Get the realpath */
		real_fname = realpath((char *)bprm->filename);

		if (IS_ERR(real_fname)) {
			pr_debug("bprm->filename realpath() error\n");
			ret = PTR_ERR(real_fname);
			if (ret == -ENOMEM)
				return ret;
			goto pass;
		}
		pr_debug("real_fname: %s\n", real_fname);

		/* Check out memfd file (memfd_create) */
		if (!strncmp(real_fname, memfd, strlen(memfd))) {
			pr_warning("bprm_change_interp, Unusual case : %s\n", real_fname);
			kfree(real_fname);
			kfree(real_interp);
			return -EPERM;
		}
		
		/* Check unauthorized path */
		if ((pret = path_filter(real_fname))) {
			pr_warning("bprm_change_interp() : unauthorized script file blocked : %s\n", real_fname);
			kfree(real_fname);
			kfree(real_interp);
			return -EPERM;
		}

		eret = envp_filter();
		if((eret != 0)) {
			pr_debug("bprm-envp_filter() = %d\n", eret);
			kfree(real_fname);
			kfree(real_interp);
			return -EPERM;
		}
		kfree(real_fname);
	}
	kfree(real_interp);

pass:	
	ret = real_bprm_change_interp(interp, bprm);
	return ret;
}


/*
 * Ftrace_hook hook_targets
 *
 * Register syscalls or kernel functions for hooking
 *
 */
static struct ftrace_hook hook_targets[] = { 
    HOOK_SYSCALL("sys_execve", fh_sys_execve, &real_sys_execve),
    HOOK_SYSCALL("sys_execveat", fh_sys_execveat, &real_sys_execveat),
    HOOK("bprm_change_interp", fh_bprm_change_interp, &real_bprm_change_interp)
};

static int gooroom_interp_lock_init(void)
{
	int err, retval;

	err = fh_install_hooks(hook_targets, ARRAY_SIZE(hook_targets));
	if (err)
		return err;

	/* Create a kobject for sysfs */
	interp_lock_kobj = kobject_create_and_add("interp_lock", fs_kobj);
	if (!interp_lock_kobj)
		return -ENOMEM;
	
	/* Create the file associated with the kobject */
	retval = sysfs_create_group(interp_lock_kobj, &attr_group);
	if (retval)
		kobject_put(interp_lock_kobj);

	lock_state = true;
	pr_info("gooroom_interp_lock loaded\n");
	
	return 0;
}
module_init(gooroom_interp_lock_init);

static void gooroom_interp_lock_exit(void)
{
	kobject_put(interp_lock_kobj);
	fh_remove_hooks(hook_targets, ARRAY_SIZE(hook_targets));
	pr_info("gooroom_interp_lock unloaded\n");
}
module_exit(gooroom_interp_lock_exit);
