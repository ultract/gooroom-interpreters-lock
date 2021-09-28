/*
 * Gooroom Interpreter Lock based on ftrace feature
 *
 * Copyright (c) 2020 ultract
 */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>

/* sysfs variables */
static bool lock_state;


/* Show a state of the interpreter lock via sysfs */
static ssize_t lock_state_show(struct kobject *kobj, struct kobj_attribute *attra, 
								  char *buf)
{
	return sprintf(buf, "%d\n", lock_state);
}

/* Change a state of the interpreter lock via sysfs */
static ssize_t lock_state_change(struct kobject *kobj, struct kobj_attribute *attr, 
									const char *buf, size_t count)
{
	int ret;

	//ret = kstrtoint(buf, 10, &lock_state);
	ret = kstrtobool(buf, &lock_state);
	if (ret < 0)
		return ret;

	pr_info("gooroom_interpreter_lock %s\n", lock_state ? "enabled" : "disabled");
	return count;
}

/* Sysfs attributes */
static struct kobj_attribute interp_lock_attribute = 
	__ATTR(lock_state, 0664, lock_state_show, lock_state_change);

/* Create a group of attributes */
static struct attribute *attrs[] = {
	&interp_lock_attribute.attr,
	NULL,
};

/* An attribute group for the kobject directory */
static struct attribute_group attr_group = {
	.attrs = attrs,
};

/* kobject for sysfs */
static struct kobject *interp_lock_kobj;
